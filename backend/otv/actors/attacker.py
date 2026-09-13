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

    # --- Auth-code replay (RFC 6749 §4.1.2 / RFC 6819 §4.4.1.1) ------------

    def capture_code(self, code: str, *, obtained_from_seq: int) -> Dict[str, Any]:
        """Capture a copy of the authorization code from the front channel.

        Unlike interception-then-injection, here the *honest* client also holds the
        code and will redeem it. The attacker keeps a copy to replay later. A
        captured code is only useful until it is spent — the single-use property is
        what decides the replay.
        """
        self._stolen_code = code
        seq = self.recorder.emit(
            actor="attacker",
            phase="redirect",
            summary="Attacker captures a copy of the authorization code.",
            detail=(
                "The code travels the front channel — the redirect in the user's "
                "browser — so the attacker can capture a copy (via Referer, history, "
                "or a log) even while the legitimate client also receives it. The "
                "attacker keeps the code to try replaying it after the client has "
                "redeemed it."
            ),
            outcome="ok",
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
                "attacker": KnowledgeState(has=["authorization_code"]),
            },
            spec_refs=[SpecRef(rfc="RFC 6819", section="§4.4.1.1")],
        )
        self._intercept_seq = seq
        return {"seq": seq}

    def replay_code(self, *, auth_server: AuthServer) -> Dict[str, Any]:
        """Replay the captured code at the token endpoint after it was redeemed.

        The honest client already spent this code, so the authorization server's
        single-use store has marked it used. The genuine ``authorization_code_
        single_use`` check (RFC 6749 §4.1.2) rejects the second redemption. Returns
        ``{"got_token": bool, "at_seq": int | None}``.
        """
        code = self._stolen_code
        assert code is not None, "replay_code called before capture_code"
        client = self.env.public_client
        # A public-client flow: the attacker presents the public client_id and the
        # captured code. No verifier is needed (the flow ran without PKCE), so
        # single use is honestly the property under test.
        token_request = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": client.redirect_uri,
            "client_id": client.client_id,
        }
        try:
            with acting(on_behalf_of="attacker", source_actor="attacker"):
                token_response = auth_server.token(token_request)
        except OAuthError as exc:
            self.recorder.emit(
                actor="attacker",
                phase="token",
                summary="Attacker's replay of the spent code is rejected.",
                detail=(
                    "The honest client already redeemed this code, so the "
                    "authorization server marked it used. Replaying the very same code "
                    "fails the single-use check and the token endpoint rejects it: a "
                    "captured authorization code is worthless once it has been spent."
                ),
                outcome="attack_blocked",
                # Truthful causality: the rejection is the single-use check the
                # endpoint just failed.
                refs=[exc.at_seq] if exc.at_seq is not None else [self.recorder.last_seq],
                http=HttpExchange(
                    request=HttpMessage(method="POST", url=self.env.token_url),
                    response=HttpMessage(status=exc.status, body={"error": exc.error}),
                    highlight=["response.body.error"],
                    source_actor="auth_server",
                    target_actor="attacker",
                ),
                spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.2")],
            )
            return {"got_token": False, "at_seq": exc.at_seq}

        # Defensive: a replay of a spent single-use code must not succeed. If it
        # ever did, record it honestly rather than hide it.
        self._access_token = token_response["access_token"]
        seq = self.recorder.emit(
            actor="attacker",
            phase="token",
            summary="Attacker's replayed code was accepted (single-use not enforced).",
            detail=(
                "The token endpoint accepted a second redemption of the same code, so "
                "single-use enforcement is not holding. This should never happen when "
                "the single-use code store is working."
            ),
            outcome="attack_success",
            refs=[self.recorder.last_seq],
            knowledge_delta={"attacker": KnowledgeState(has=["access_token"])},
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.2")],
        )
        return {"got_token": True, "at_seq": seq}

    # --- CSRF / cross-session code injection (RFC 6749 §10.12) -------------

    def stage_csrf_injection(self, code: str, *, obtained_from_seq: int) -> Dict[str, Any]:
        """Deliver the attacker's own code into the victim's client session.

        The attacker has logged in as *itself* and obtained a valid authorization
        code for the victim's client (bound to the attacker's account). It now
        delivers that code to the victim's browser via a crafted link to the
        client's callback. The victim's client cannot tell the response did not
        belong to the session it started — unless it checks ``state``.
        """
        self._stolen_code = code
        victim_client = self.env.client
        seq = self.recorder.emit(
            actor="attacker",
            phase="redirect",
            summary="Attacker crafts a CSRF callback carrying its own code.",
            detail=(
                "The attacker logged in under its own account and obtained a valid "
                "authorization code for the victim's client. It now sends the victim a "
                "crafted link to the client's callback carrying that code (but not the "
                "victim client's 'state'). If the victim follows it, the client will "
                "redeem a code bound to the ATTACKER's account — binding the victim's "
                "session to the attacker unless a 'state' check rejects the mismatch."
            ),
            outcome="ok",
            refs=[obtained_from_seq],
            http=HttpExchange(
                request=HttpMessage(
                    method="GET",
                    url=f"{victim_client.redirect_uri}?code={code}",
                    body={"code": code},
                ),
                response=HttpMessage(status=302, body={"delivered_to": "victim_browser"}),
                highlight=["request.body.code"],
                source_actor="attacker",
                target_actor="client",
            ),
            knowledge_delta={
                # The attacker holds a code for its OWN account and, crucially, does
                # not hold the victim client's per-session 'state'.
                "attacker": KnowledgeState(
                    has=["authorization_code(attacker_account)"],
                    lacks=["victim_session_state"],
                ),
            },
            spec_refs=[SpecRef(rfc="RFC 6749", section="§10.12")],
        )
        return {"seq": seq, "code": code}

    def note_cross_session_binding(self, *, at_seq: int) -> Dict[str, Any]:
        """Record the achieved login-CSRF binding (state was not enforced)."""
        seq = self.recorder.emit(
            actor="attacker",
            phase="resource",
            summary="Cross-session binding: the victim's client is bound to the attacker.",
            detail=(
                "With no 'state' check the victim's client accepted the injected code "
                "and redeemed it. The token — and the profile it unlocks — belong to "
                "the ATTACKER's account, so the victim is now operating inside the "
                "attacker's account (anything the victim does lands there). This is the "
                "login-CSRF outcome that binding the response to the session with "
                "'state' prevents."
            ),
            outcome="attack_success",
            refs=[at_seq],
            knowledge_delta={
                "attacker": KnowledgeState(has=["victim_client_bound_to_attacker"]),
            },
            spec_refs=[SpecRef(rfc="RFC 6749", section="§10.12")],
        )
        return {"seq": seq}

    def access_resource(self, *, resource_server: ResourceServer) -> Dict[str, Any]:
        """Use the stolen-flow access token to read the victim's protected data."""
        assert self._access_token is not None, "access_resource without a token"
        request = {
            "url": self.env.resource_url,
            "headers": {"Authorization": f"Bearer {self._access_token}"},
        }
        with acting(on_behalf_of="attacker", source_actor="attacker"):
            return resource_server.get_resource(request)
