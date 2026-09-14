"""Client-credentials grant + client-authentication methods (Phase 5).

Two self-registering runners live here, both keyed off ``grant ==
"client_credentials"``:

- ``client_credentials`` — the clean machine-to-machine flow (RFC 6749 §4.4).
  **There is no user and no browser:** the client authenticates *as itself* at the
  token endpoint and the authorization server issues a token whose subject is the
  *client*. This is the M2M vs user-based contrast the design keeps returning to.

- ``static_secret_leak`` — the attack (RFC 6749 §10.3): a leaked, never-rotating
  ``client_secret`` is replayed to impersonate the client. Whether it wins is
  decided by the ``client_auth`` capability's method:
    * ``client_secret_basic`` / ``client_secret_post`` — the shared static secret
      *is* the authority, so a replay authenticates and the attacker gets a token.
    * ``private_key_jwt`` — the secret never transits; the most an attacker can
      capture is a spent ``client_assertion``, which is short-lived and
      ``jti``-bound. Replaying it fails real signature/exp verification, and a new
      one cannot be forged without the client's private key.

Client authentication is **real**: secret methods compare the presented secret to
the registered one; ``private_key_jwt`` signs an assertion with a genuine EC key
and the authorization server verifies it against the registered public key
(ES256), enforcing ``aud`` = token endpoint and a fresh, unexpired, unreplayed
``jti`` (RFC 7523 §3). The block a runner attributes to ``client_auth`` is the
check the protocol actually failed, never a scripted verdict.
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import jwt

from ... import crypto
from ...actors.auth_server import OAuthError
from ...actors.environment import ISSUER, RESOURCE_AUDIENCE, TOKEN_URL
from ...contract import (
    Check,
    HttpExchange,
    HttpMessage,
    KnowledgeState,
    ScenarioConfig,
    SpecRef,
    Trace,
    Verdict,
)
from ...recorder import Recorder
from ...trace_context import acting
from . import Runner, register
from .support import CHECK_TO_CAPABILITY, event_at, new_run_id

# The registered machine-to-machine (confidential) client. Its facts live here
# rather than in the shared environment because they are specific to this phase:
# a client-credentials principal with a static secret AND a registered public key
# for private_key_jwt. In a real deployment these are the client's registration
# metadata at the authorization server.
SERVICE_CLIENT_ID = "demo-service-client"
SERVICE_CLIENT_SECRET = "svc-s3cr3t-01HXZ-never-rotated"  # static; the whole point
SERVICE_SCOPE = "reports.read reports.write"

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

_METHODS = ("client_secret_basic", "client_secret_post", "private_key_jwt")


def client_auth_method(config: ScenarioConfig) -> str:
    """The client-authentication method for this run (default ``client_secret_basic``).

    Read from the ``client_auth`` capability's ``method`` param. Resolved even when
    the capability is not marked ``active``, because a confidential client always
    authenticates *somehow*; ``client_secret_basic`` is the conventional default.
    """
    st = config.capabilities.get("client_auth")
    method = st.params.get("method") if st is not None else None
    return method if method in _METHODS else "client_secret_basic"


# --- Real private_key_jwt key material (RFC 7523 §2.2) ---------------------
#
# The client's key and its client_assertion sign/verify are the SAME canonical
# helpers the JWT bearer grant (Phase 4) uses — ``crypto.SigningKey`` /
# ``crypto.sign_assertion`` / ``crypto.verify_assertion`` — just generated as an
# EC (ES256) key instead of RSA, since ``key.alg`` travels with the key and both
# functions key off it. See ``otv/crypto.py`` for the shared implementation.


def _generate_client_key() -> crypto.SigningKey:
    return crypto.SigningKey.generate(kid=f"client-key-{uuid.uuid4().hex[:8]}", alg="ES256")


@dataclass
class ServiceClient:
    """The registered confidential client the token endpoint recognizes."""

    client_id: str = SERVICE_CLIENT_ID
    client_secret: str = SERVICE_CLIENT_SECRET
    scope: str = SERVICE_SCOPE
    key: crypto.SigningKey = field(default_factory=_generate_client_key)


def _redact(secret: str) -> str:
    return secret[:3] + "…(redacted)" if secret else ""


def _basic_header(client_id: str, secret: str) -> str:
    """The recorded ``Authorization: Basic`` header, secret redacted.

    Real HTTP Basic auth base64-encodes ``client_id:secret`` — but this is the
    header as it goes into the TRACE, not the wire, and the trace must never
    display a full credential (real Basic auth over TLS is fine; a visualizer
    that echoes the whole secret back in plaintext is not, and would teach
    "Basic is safe to log"). Redact the secret the same way the
    ``client_secret_post`` body does before encoding, so only a `client_id:`
    plus a truncated, clearly-redacted tail ever appears.
    """
    raw = f"{client_id}:{_redact(secret)}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


# --- The client-credentials token endpoint (real, self-contained) ----------
# Kept local to this phase's runner so the shared AuthServer (whose token()
# endpoint is authorization-code specific) is not edited. It signs REAL RS256
# access tokens and verifies client authentication for real.


class M2MTokenEndpoint:
    """A real ``/oauth/token`` for the client-credentials grant.

    Signs genuine RS256 access tokens (subject = the *client*) and enforces client
    authentication for real: a secret comparison for the ``client_secret_*``
    methods, and full ES256 assertion verification (signature via the registered
    public key, ``aud`` = this endpoint, unexpired, and a one-time ``jti``) for
    ``private_key_jwt``.
    """

    def __init__(self, recorder: Recorder, registered: ServiceClient):
        self.recorder = recorder
        self.registered = registered
        self.signing_key = crypto.SigningKey.generate(kid="as-cc-2026-09")
        self._used_jtis: Set[str] = set()

    def jwks(self) -> Dict[str, Any]:
        return self.signing_key.jwks()

    # -- receive + authenticate + issue -----------------------------------

    def token(
        self,
        *,
        method: str,
        presented: Dict[str, Any],
        presenter: str,
    ) -> Dict[str, Any]:
        """Handle a client-credentials token request from ``presenter``.

        Emits the receive step, a first-class client-authentication ``check``, and
        (on success) the token-issuance step. Raises :class:`OAuthError` — carrying
        the ``check`` seq — when authentication fails.
        """
        self._emit_receive(method=method, presented=presented, presenter=presenter)
        check_seq, ok, actual = self._emit_client_auth_check(
            method=method, presented=presented
        )
        if not ok:
            raise OAuthError(
                "invalid_client",
                f"client authentication failed ({actual})",
                status=401,
                at_seq=check_seq,
            )
        return self._emit_issue(presenter=presenter, at_seq=check_seq)

    def _emit_receive(
        self, *, method: str, presented: Dict[str, Any], presenter: str
    ) -> int:
        headers: Dict[str, Any] = {"Content-Type": "application/x-www-form-urlencoded"}
        body: Dict[str, Any] = {"grant_type": "client_credentials", "scope": SERVICE_SCOPE}
        if method == "client_secret_basic":
            headers["Authorization"] = _basic_header(
                self.registered.client_id, presented.get("client_secret", "")
            )
            highlight = ["request.headers.Authorization"]
            how = "in an HTTP Basic Authorization header"
        elif method == "client_secret_post":
            body["client_id"] = self.registered.client_id
            body["client_secret"] = _redact(presented.get("client_secret", ""))
            highlight = ["request.body.client_secret"]
            how = "as a client_secret in the request body"
        else:  # private_key_jwt
            body["client_assertion_type"] = CLIENT_ASSERTION_TYPE
            body["client_assertion"] = presented.get("client_assertion", "")
            highlight = ["request.body.client_assertion"]
            how = "as a signed client_assertion (JWT)"
        return self.recorder.emit(
            actor="auth_server",
            phase="token",
            summary="Token endpoint receives a client-credentials token request.",
            detail=(
                "The client-credentials grant has no user and no browser: the client "
                "requests a token for itself, authenticating directly at the token "
                f"endpoint {how}. The server will authenticate the client, then issue a "
                "token whose subject is the client itself."
            ),
            outcome="ok",
            http=HttpExchange(
                request=HttpMessage(
                    method="POST", url=TOKEN_URL, headers=headers, body=body
                ),
                response=HttpMessage(status=200, body={"processing": True}),
                highlight=highlight,
                source_actor=presenter,
                target_actor="auth_server",
            ),
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.4.2")],
        )

    def _emit_client_auth_check(
        self, *, method: str, presented: Dict[str, Any]
    ) -> Tuple[int, bool, str]:
        if method in ("client_secret_basic", "client_secret_post"):
            ok = presented.get("client_secret") == self.registered.client_secret
            actual = "secret matched" if ok else "secret mismatch"
            check = Check(
                name="client_secret_auth",
                rule="presented client_secret == registered client_secret",
                expected="the registered static client secret",
                actual=actual,
                result="PASS" if ok else "FAIL",
                spec_ref=SpecRef(rfc="RFC 6749", section="§2.3.1"),
            )
            detail = (
                "The client authenticates with a shared static secret. The server "
                "compares the presented secret to the one registered for the client. "
                "A static secret is symmetric: whoever holds it can authenticate as "
                "the client, and it does not change over time."
            )
            spec = SpecRef(rfc="RFC 6749", section="§2.3.1")
        else:  # private_key_jwt
            ok, actual = self._verify_assertion(presented.get("client_assertion", ""))
            check = Check(
                name="private_key_jwt_auth",
                rule=(
                    "verify client_assertion signature with the registered public key "
                    "AND aud == token endpoint AND unexpired AND jti unused"
                ),
                expected="a fresh, correctly-signed assertion with an unused jti",
                actual=actual,
                result="PASS" if ok else "FAIL",
                spec_ref=SpecRef(rfc="RFC 7523", section="§3"),
            )
            detail = (
                "The client proves possession of its private key with a short-lived, "
                "signed client_assertion. The server verifies the signature against the "
                "client's registered PUBLIC key, checks the audience is this token "
                "endpoint, that the assertion has not expired, and that its jti has not "
                "been seen before. No secret ever transits the wire, so there is no "
                "static credential to leak."
            )
            spec = SpecRef(rfc="RFC 7523", section="§3")
        seq = self.recorder.emit(
            actor="auth_server",
            phase="token",
            summary="Token endpoint authenticates the client.",
            detail=detail,
            outcome="ok" if check.result == "PASS" else "blocked",
            check=check,
            spec_refs=[spec],
        )
        return seq, check.result == "PASS", check.actual or ""

    def _verify_assertion(self, assertion: str) -> Tuple[bool, str]:
        """Real ES256 verification of a client_assertion (RFC 7523 §3).

        Delegates to :func:`crypto.verify_assertion` — the same canonical
        verifier the JWT bearer grant uses for its (RSA) user assertions —
        against the client's registered EC public key; only the ``sub`` ==
        client and the one-time-``jti`` checks are specific to client
        authentication and stay local here.
        """
        if not assertion:
            return False, "no client_assertion presented"
        try:
            claims = crypto.verify_assertion(
                assertion,
                jwks=self.registered.key.jwks(),
                issuer=self.registered.client_id,
                audience=TOKEN_URL,
            )
        except jwt.ExpiredSignatureError:
            return False, "assertion expired (captured from an earlier flow)"
        except jwt.PyJWTError as exc:
            return False, f"assertion rejected ({type(exc).__name__})"
        if claims.get("sub") != self.registered.client_id:
            return False, "assertion sub is not the client"
        jti = claims.get("jti")
        if jti in self._used_jtis:
            return False, "assertion jti already used (replay)"
        self._used_jtis.add(jti)
        return True, "assertion verified"

    def _emit_issue(self, *, presenter: str, at_seq: int) -> Dict[str, Any]:
        access_token = crypto.sign_access_token(
            self.signing_key,
            issuer=ISSUER,
            subject=self.registered.client_id,  # the CLIENT is the principal
            audience=RESOURCE_AUDIENCE,
            client_id=self.registered.client_id,
            scope=SERVICE_SCOPE,
            ttl_seconds=300,
        )
        self.recorder.emit(
            actor="auth_server",
            phase="token",
            summary="Authorization server issues a token to the client itself.",
            detail=(
                "Client authentication passed. The server signs a real RS256 access "
                "token whose subject is the CLIENT (there is no user in this grant) and "
                "returns it. The token represents the client acting as itself."
            ),
            outcome="ok",
            refs=[at_seq],
            http=HttpExchange(
                request=HttpMessage(method="POST", url=TOKEN_URL),
                response=HttpMessage(
                    status=200,
                    headers={"Content-Type": "application/json"},
                    body={
                        "access_token": access_token,
                        "token_type": "Bearer",
                        "expires_in": 300,
                        "scope": SERVICE_SCOPE,
                    },
                ),
                highlight=["response.body.access_token"],
                source_actor="auth_server",
                target_actor=presenter,
            ),
            knowledge_delta={
                "auth_server": KnowledgeState(has=["client_principal_token"]),
            },
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.4.3")],
        )
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 300,
            "scope": SERVICE_SCOPE,
        }


# --- Runner 1: the clean client-credentials flow ---------------------------


def _matches_happy(config: ScenarioConfig) -> bool:
    return config.grant == "client_credentials" and not config.active_attacks()


def _run_happy(config: ScenarioConfig) -> Trace:
    recorder = Recorder(new_run_id(), config)
    registered = ServiceClient()
    endpoint = M2MTokenEndpoint(recorder, registered)
    method = client_auth_method(config)

    with acting(on_behalf_of="client", source_actor="client"):
        recorder.emit(
            actor="client",
            phase="token",
            summary="Client begins the client-credentials grant (no user involved).",
            detail=(
                "Unlike the authorization-code grant, there is no user, browser, "
                "redirect, or consent here. The client acts on its own behalf — it IS "
                "the principal — and goes straight to the token endpoint to "
                "authenticate and request a token."
            ),
            outcome="ok",
            knowledge_delta={
                "client": KnowledgeState(has=["client_id", "client_credential"]),
            },
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.4")],
        )
        presented = _client_presented(registered, method, fresh=True)
        token_response = endpoint.token(
            method=method, presented=presented, presenter="client"
        )
        recorder.emit(
            actor="client",
            phase="token",
            summary="Client holds an access token issued to itself as the principal.",
            detail=(
                "The client received a token whose subject is the client, not a user. "
                "It can now call machine-to-machine APIs as itself. No user ever "
                "participated in this exchange."
            ),
            outcome="ok",
            knowledge_delta={"client": KnowledgeState(has=["access_token"])},
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.4.3")],
        )

    got = bool(token_response.get("access_token"))
    verdict = Verdict(
        attacker_got_token=False,
        user_got_token=False,  # there is no user in the client-credentials grant
        user_accessed_resource=False,
        one_line=(
            "Client obtained an access token as its OWN principal via the "
            f"client-credentials grant ({method}). There is no user in this grant — "
            "the client authenticated directly and the token's subject is the client "
            "itself. Attacker obtained an access token: NO — no attack was attempted."
        )
        if got
        else "Client did not obtain a token.",
        blocked_at_seq=None,
        responsible_capability=None,
    )
    return recorder.seal(verdict)


# --- Runner 2: the static-secret-leak attack -------------------------------


def _matches_leak(config: ScenarioConfig) -> bool:
    return (
        config.grant == "client_credentials"
        and "static_secret_leak" in config.active_attacks()
    )


def _run_leak(config: ScenarioConfig) -> Trace:
    recorder = Recorder(new_run_id(), config)
    registered = ServiceClient()
    endpoint = M2MTokenEndpoint(recorder, registered)
    method = client_auth_method(config)

    # 1) The attacker obtains the leaked client credential. For a static secret it
    #    is the secret itself; for private_key_jwt the secret never transits, so the
    #    most that can leak is a spent, short-lived assertion captured from an
    #    earlier flow (modeled as already expired). The step summary is identical
    #    across methods so the paired diff stays the same flow until the outcome.
    with acting(on_behalf_of="attacker", source_actor="attacker"):
        captured = _attacker_captured(registered, method)
        recorder.emit(
            actor="attacker",
            phase="token",
            summary="Attacker obtains the leaked client credential.",
            detail=captured["capture_detail"],
            outcome="ok",
            http=HttpExchange(
                request=HttpMessage(
                    method="GET",
                    url="https://attacker.evil.internal/harvest",
                    headers={"X-Observed": captured["source"]},
                ),
                response=HttpMessage(status=200, body={"captured": captured["display"]}),
                highlight=["response.body.captured"],
                source_actor="attacker",
                target_actor="attacker",
            ),
            knowledge_delta={"attacker": KnowledgeState(**captured["knowledge"])},
            spec_refs=[SpecRef(rfc="RFC 6749", section="§10.3")],
        )

        # 2) The attacker replays the leaked credential to impersonate the client.
        try:
            token_response = endpoint.token(
                method=method, presented=captured["presented"], presenter="attacker"
            )
        except OAuthError as exc:
            block_seq = _emit_attacker_blocked(recorder, method, exc)
            return recorder.seal(_leak_blocked_verdict(recorder, method, exc.at_seq or block_seq))

        # 3) Secret methods: the replay authenticated and the attacker holds a
        #    token. Stays inside the attacker's `acting` block — this is the
        #    attacker's own win, not something done "on behalf of" the user.
        access_token = token_response["access_token"]
        win_seq = recorder.emit(
            actor="attacker",
            phase="token",
            summary="Attacker obtains a client-principal token by impersonation.",
            detail=(
                "The static secret is the whole authority. Replaying the leaked secret "
                "authenticates the attacker AS the client, so the token endpoint issues a "
                "token for the client's principal. Because the secret never rotates, this "
                "impersonation persists until someone notices and rotates it."
            ),
            outcome="attack_success",
            refs=[recorder.last_seq],
            knowledge_delta={"attacker": KnowledgeState(has=["client_principal_token"])},
            spec_refs=[SpecRef(rfc="RFC 6749", section="§10.3")],
        )
    assert access_token  # a real signed JWT was issued to the attacker
    return recorder.seal(_leak_success_verdict(method, win_seq))


def _client_presented(
    registered: ServiceClient, method: str, *, fresh: bool
) -> Dict[str, Any]:
    """What a *legitimate* client presents for a given method."""
    if method == "private_key_jwt":
        assertion = crypto.sign_assertion(
            registered.key,
            issuer=registered.client_id,
            subject=registered.client_id,
            audience=TOKEN_URL,
        )
        return {"client_assertion": assertion}
    return {"client_secret": registered.client_secret}


def _attacker_captured(registered: ServiceClient, method: str) -> Dict[str, Any]:
    """Model what the attacker captured, and what it presents on replay."""
    if method == "private_key_jwt":
        # What transits is a client_assertion. The attacker captures one from an
        # earlier exchange — but it is short-lived, so by replay time it is expired
        # (modeled with a past iat/exp), and the attacker lacks the private key to
        # forge a fresh one. This is REAL: the AS runs genuine ES256 + exp checks.
        assertion = crypto.sign_assertion(
            registered.key,
            issuer=registered.client_id,
            subject=registered.client_id,
            audience=TOKEN_URL,
            ttl_seconds=60,
            iat_offset=-600,  # issued ~10 minutes ago → already expired at replay
        )
        return {
            "source": "captured client_assertion (from an earlier flow)",
            "display": "client_assertion (JWT, already expired)",
            "capture_detail": (
                "With private_key_jwt the client secret never leaves the client, so "
                "there is no static secret to steal. The most an attacker can capture "
                "off the wire is a client_assertion from an earlier exchange — a "
                "short-lived, signed JWT. The attacker holds a copy but does NOT hold "
                "the client's private key."
            ),
            "knowledge": {
                "has": ["captured_client_assertion"],
                "lacks": ["client_private_key"],
            },
            "presented": {"client_assertion": assertion},
        }
    return {
        "source": "leaked config / log dump",
        "display": _redact(registered.client_secret),
        "capture_detail": (
            "The client's static client_secret leaked — a committed config file, a "
            "log line, or an environment dump. The secret never rotates, so a captured "
            "copy is the client's full authority for as long as it stays valid (which "
            "is: indefinitely)."
        ),
        "knowledge": {"has": ["leaked_client_secret"], "lacks": []},
        "presented": {"client_secret": registered.client_secret},
    }


def _emit_attacker_blocked(recorder: Recorder, method: str, exc: OAuthError) -> int:
    return recorder.emit(
        actor="attacker",
        phase="token",
        summary="Attacker's impersonation attempt is rejected.",
        detail=(
            "The token endpoint rejects the replay. With private_key_jwt the attacker "
            "could only present a captured assertion, which is short-lived and "
            "jti-bound: it fails real verification, and the attacker cannot mint a "
            "fresh one without the client's private key. Nothing that transited the "
            "wire is enough to impersonate the client."
        ),
        outcome="attack_blocked",
        refs=[exc.at_seq] if exc.at_seq is not None else [recorder.last_seq],
        http=HttpExchange(
            request=HttpMessage(method="POST", url=TOKEN_URL),
            response=HttpMessage(status=exc.status, body={"error": exc.error}),
            highlight=["response.body.error"],
            source_actor="auth_server",
            target_actor="attacker",
        ),
        spec_refs=[SpecRef(rfc="RFC 7523", section="§3")],
    )


def _leak_success_verdict(method: str, at_seq: int) -> Verdict:
    return Verdict(
        attacker_got_token=True,
        user_got_token=False,  # no user in this grant
        user_accessed_resource=False,
        one_line=(
            "Attacker obtained an access token: YES — a leaked static client secret "
            f"({method}) is all that is required to authenticate as the client. The "
            "secret never rotates, so the leak is permanent impersonation. Switching "
            "the client to private_key_jwt removes the static secret entirely."
        ),
        blocked_at_seq=None,
        responsible_capability=None,
        responsible_capabilities=[],
    )


def _leak_blocked_verdict(recorder: Recorder, method: str, at_seq: Optional[int]) -> Verdict:
    blocking = event_at(recorder, at_seq)
    responsible: Optional[str] = None
    if blocking is not None and blocking.check is not None:
        responsible = CHECK_TO_CAPABILITY.get(blocking.check.name)
    caps = [responsible] if responsible else []
    return Verdict(
        attacker_got_token=False,
        user_got_token=False,
        user_accessed_resource=False,
        one_line=(
            "Attacker obtained an access token: NO — with private_key_jwt there is no "
            "static secret to leak. The captured client_assertion is short-lived and "
            "jti-bound, so replaying it fails verification, and a fresh one cannot be "
            "forged without the client's private key. The identical leak that wins "
            "against a static secret is defeated here."
        ),
        blocked_at_seq=at_seq,
        responsible_capability=responsible,
        responsible_capabilities=caps,
    )


register(Runner(id="client_credentials", matches=_matches_happy, run=_run_happy))
register(Runner(id="static_secret_leak", matches=_matches_leak, run=_run_leak))
