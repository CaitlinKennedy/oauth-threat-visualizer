"""The Attacker actor.

A first-class actor in the design (DESIGN.md §3), modeled with its own service
and its own origin. Exposed as a service-API interface so later phases add more
real attack methods (replay, phishing chains) behind the same seam every other
actor uses.

Phase 1 makes the attacker **real** for auth-code injection (RFC 9700 §4.5): it
obtains an authorization code from the front channel and attempts to redeem it at
the *real* token endpoint. Whether that succeeds is decided entirely by the real
protocol — with PKCE the attacker cannot produce the matching ``code_verifier``,
so the genuine ``pkce_verifier_match`` check (real S256 arithmetic) rejects it.
The attacker only ever holds what it could realistically obtain; that is exactly
what ``knowledge_delta`` exposes (it has the ``code``, it lacks the
``code_verifier``).
"""

from __future__ import annotations

import abc
from typing import Any, Dict, Optional

from .. import crypto
from ..contract import HttpExchange, HttpMessage, KnowledgeState, SpecRef
from ..recorder import Recorder
from ..trace_context import acting
from .auth_server import AuthServer, OAuthError
from .environment import Environment
from .resource_server import ResourceServer


class Attacker(abc.ABC):
    """Service-API interface for the adversary."""

    @abc.abstractmethod
    def is_active(self) -> bool:
        """Whether any attack is configured to run in this scenario."""


class AttackerImpl(Attacker):
    def __init__(self, recorder: Recorder, env: Environment, *, active: bool = False):
        self.recorder = recorder
        self.env = env
        self.origin = "https://attacker.evil.internal"
        self._active = active
        self._stolen_code: Optional[str] = None
        self._intercept_seq: Optional[int] = None
        self._access_token: Optional[str] = None

    def is_active(self) -> bool:
        return self._active

    # --- Auth-code injection (RFC 9700 §4.5) -------------------------------

    def intercept_code(self, code: str, *, obtained_from_seq: int) -> Dict[str, Any]:
        """Model a realistic acquisition of the victim's authorization code.

        The code travels the front channel (the redirect through the browser), so
        it can leak — via the Referer header, browser history, an open redirect, a
        proxy log, or a mix-up. The attacker captures it. Crucially the code is not
        a secret bound to the attacker: possessing it is not, by itself, authority
        to redeem it — that is the gap PKCE closes.
        """
        self._stolen_code = code
        seq = self.recorder.emit(
            actor="attacker",
            phase="redirect",
            summary="Attacker obtains the victim's authorization code.",
            detail=(
                "The authorization code is delivered through the front channel — the "
                "redirect in the user's browser — where it is exposed to leakage "
                "(Referer, history, an open redirect, or logs). The attacker captures "
                "it. The flow used a public client, so the client_id is not a secret "
                "either. What the attacker does NOT have is the per-request "
                "code_verifier, which never left the legitimate client instance."
            ),
            outcome="ok",  # the acquisition itself succeeds; the redemption is what's tested
            refs=[obtained_from_seq],
            http=HttpExchange(
                request=HttpMessage(
                    method="GET",
                    url=f"{self.origin}/harvest",
                    headers={"X-Observed": "front-channel redirect"},
                ),
                response=HttpMessage(status=200, body={"captured_code": code}),
                highlight=["response.body.captured_code"],
                source_actor="auth_server",
                target_actor="attacker",
            ),
            knowledge_delta={
                # The attacker holds the code and the PUBLIC client_id (not a
                # secret), so client authentication is not the blocker. The one
                # thing it cannot supply is the verifier.
                "attacker": KnowledgeState(
                    has=["authorization_code", "public_client_id"],
                    lacks=["code_verifier"],
                ),
            },
            spec_refs=[
                SpecRef(rfc="RFC 9700", section="§4.5"),
                SpecRef(rfc="RFC 7636", section="§1"),
            ],
        )
        self._intercept_seq = seq
        return {"seq": seq}

    def redeem_code(self, *, auth_server: AuthServer) -> Dict[str, Any]:
        """Redeem the stolen code at the real token endpoint, as the attacker.

        The flow used a public client, so the attacker simply presents the public
        client_id (no secret exists) plus the stolen code and its *own* freshly
        generated verifier — it cannot know the victim client's secret verifier.
        The real token endpoint decides the outcome: without PKCE there is no
        challenge to check and a token is issued for the victim; with PKCE the
        genuine S256 check rejects the mismatch. Returns ``{"got_token": bool,
        "at_seq": int | None, "responsible_check": str | None}``.
        """
        code = self._stolen_code
        assert code is not None, "redeem_code called before intercept_code"
        client = self.env.public_client
        # The attacker's own session verifier — it does not match the victim's
        # challenge, and the attacker cannot reverse S256 to make one that does.
        attacker_verifier = crypto.new_code_verifier()
        # A public client has no secret; the attacker presents only the public
        # client_id, so nothing here hand-waves a stolen credential.
        token_request = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": client.redirect_uri,
            "client_id": client.client_id,
            "code_verifier": attacker_verifier,
        }

        # Drive the REAL token endpoint as the attacker peer (ambient request scope
        # carries the caller identity; the interface stays pure protocol). The
        # endpoint emits its own receive/check/issue steps attributed to the
        # attacker; we then record the attacker observing the result.
        try:
            with acting(on_behalf_of="attacker", source_actor="attacker"):
                token_response = auth_server.token(token_request)
        except OAuthError as exc:
            self.recorder.emit(
                actor="attacker",
                phase="token",
                summary="Attacker's stolen-code redemption is rejected.",
                detail=(
                    "The token endpoint rejects the exchange. The attacker presented a "
                    "valid, unused, correctly-bound code for the public client — every "
                    "binding except one. It could not present a code_verifier whose "
                    "S256 hash equals the code_challenge the legitimate client "
                    "registered, so PKCE stops the injection here. No token is issued "
                    "to the attacker."
                ),
                outcome="attack_blocked",
                # Truthful causality: the rejection the attacker observes is the
                # decisive check the endpoint just failed.
                refs=[exc.at_seq] if exc.at_seq is not None else [self.recorder.last_seq],
                http=HttpExchange(
                    request=HttpMessage(method="POST", url=self.env.token_url),
                    response=HttpMessage(status=exc.status, body={"error": exc.error}),
                    highlight=["response.body.error"],
                    source_actor="auth_server",
                    target_actor="attacker",
                ),
                spec_refs=[SpecRef(rfc="RFC 7636", section="§4.6")],
            )
            return {"got_token": False, "at_seq": exc.at_seq, "responsible_check": None}

        # No PKCE: the endpoint had no challenge to check, so the injection succeeds
        # and the attacker holds a token minted for the victim's subject.
        self._access_token = token_response["access_token"]
        seq = self.recorder.emit(
            actor="attacker",
            phase="token",
            summary="Attacker obtains an access token for the victim.",
            detail=(
                "Without PKCE the token endpoint has no way to tell that the redeemer "
                "is not the client instance that started the flow: a valid, unused, "
                "correctly-bound code is all it requires. It issues an access token "
                "scoped to the victim's subject, and the attacker now holds it."
            ),
            outcome="attack_success",
            refs=[self.recorder.last_seq],  # the endpoint's issue step
            knowledge_delta={
                "attacker": KnowledgeState(has=["access_token"]),
            },
            spec_refs=[SpecRef(rfc="RFC 9700", section="§4.5")],
        )
        return {"got_token": True, "at_seq": seq, "responsible_check": None}

    def access_resource(self, *, resource_server: ResourceServer) -> Dict[str, Any]:
        """Use the stolen-flow access token to read the victim's protected data."""
        assert self._access_token is not None, "access_resource without a token"
        request = {
            "url": self.env.resource_url,
            "headers": {"Authorization": f"Bearer {self._access_token}"},
        }
        with acting(on_behalf_of="attacker", source_actor="attacker"):
            return resource_server.get_resource(request)
