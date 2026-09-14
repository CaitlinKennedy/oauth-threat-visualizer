"""The IdP / Authorization Server.

Hand-rolled OAuth 2.0 authorization-code endpoints on real primitives so every
protocol step and check is ours to instrument. It implements:

- ``/oauth/authorize`` — validates the client, authenticates the (synthetic)
  user, records consent, and mints a **single-use** authorization code bound to
  the client and redirect URI.
- ``/oauth/token`` — authenticates the confidential client, redeems the code
  (enforcing single use, redirect-URI match, and client binding), and signs a
  **real** RS256 JWT access token.
- ``/.well-known/jwks.json`` — publishes the public signing key.

PKCE, DPoP, and introspection are layered on top through the capability catalog.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .. import crypto, trace_context
from ..contract import Check, HttpExchange, HttpMessage, KnowledgeState, SpecRef
from ..recorder import Recorder
from .environment import Environment


class OAuthError(Exception):
    """An OAuth protocol error (maps to an error response at an endpoint).

    ``at_seq`` records the seq of the ``check`` event that produced the rejection,
    so a caller (e.g. the attacker observing the rejection) can anchor its own
    step's causal ``refs`` at the truthful decisive step rather than guessing.
    """

    def __init__(
        self, error: str, description: str, status: int = 400, at_seq: int | None = None
    ):
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description
        self.status = status
        self.at_seq = at_seq


@dataclass
class _StoredCode:
    client_id: str
    redirect_uri: str
    sub: str
    scope: str
    used: bool = False
    # PKCE binding (RFC 7636): the challenge the client registered at /authorize,
    # stored with the code so the token endpoint can require a matching verifier.
    # ``None`` when the flow ran without PKCE.
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None
    # The seq at which this code (and its challenge) was issued, so the
    # token-endpoint checks can ref the truthful causal origin of the code.
    issue_seq: Optional[int] = None


class AuthServer(abc.ABC):
    """Service-API interface for the IdP / authorization server.

    Public methods are named for the endpoints a standalone AS service would
    expose over REST; callers depend only on this interface.
    """

    @abc.abstractmethod
    def jwks(self) -> Dict[str, Any]:
        """Return the public signing keys (the ``/.well-known/jwks.json`` body)."""

    @abc.abstractmethod
    def authorize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle an authorization request (``GET /oauth/authorize``).

        Validates the client and redirect URI, authenticates the user, records
        consent, and mints a single-use code. Returns
        ``{"code": ..., "state": ..., "redirect_uri": ...}``.
        """

    @abc.abstractmethod
    def token(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Redeem a code for a signed access token (``POST /oauth/token``).

        Enforces client authentication, grant type, single-use redemption,
        redirect-URI match, and client binding. Returns the token response.
        """


class AuthServerImpl(AuthServer):
    def __init__(self, recorder: Recorder, env: Environment):
        self.recorder = recorder
        self.env = env
        self.signing_key = crypto.SigningKey.generate(kid="as-2026-09")
        self._codes: Dict[str, _StoredCode] = {}

    # --- JWKS --------------------------------------------------------------

    def jwks(self) -> Dict[str, Any]:
        return self.signing_key.jwks()

    # --- Authorization endpoint -------------------------------------------

    def authorize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle an authorization request and return the redirect parameters.

        Emits: receive request, client/redirect-URI registration check,
        authenticate + consent, issue code.
        """
        response_type = params.get("response_type")
        client_id = params.get("client_id")
        redirect_uri = params.get("redirect_uri")
        # Resolve the requested client from the registry (confidential or public).
        looked = self.env.client_by_id(client_id)
        scope = params.get("scope", looked.scope if looked else self.env.client.scope)
        state = params.get("state")
        # PKCE (RFC 7636): the client MAY bind the code to a per-request verifier by
        # sending a challenge here. When present, the token endpoint will require a
        # matching verifier — this is what defeats code injection.
        code_challenge = params.get("code_challenge")
        code_challenge_method = params.get("code_challenge_method")

        request_body: Dict[str, Any] = {
            "response_type": response_type,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
        }
        highlight = [
            "request.body.client_id",
            "request.body.redirect_uri",
            "request.body.response_type",
        ]
        if code_challenge is not None:
            request_body["code_challenge"] = code_challenge
            request_body["code_challenge_method"] = code_challenge_method
            highlight.append("request.body.code_challenge")

        receive_seq = self.recorder.emit(
            actor="auth_server",
            phase="authorize",
            summary="Authorization server receives the authorization request.",
            detail=(
                "The user's browser arrives at the authorization endpoint carrying the "
                "client's request. The server checks that the client is registered, that "
                "the redirect URI exactly matches one it registered, and that the "
                "response type is 'code' for the authorization-code grant."
                + (
                    " The request also carries a PKCE code_challenge, which the server "
                    "will bind to the code it issues."
                    if code_challenge is not None
                    else ""
                )
            ),
            outcome="ok",
            http=HttpExchange(
                request=HttpMessage(
                    method="GET",
                    url=self.env.authorize_url,
                    headers={"Host": "auth.oauthlab.internal"},
                    body=request_body,
                ),
                response=HttpMessage(status=200, body={"page": "login_and_consent"}),
                highlight=highlight,
                source_actor="client",
                target_actor="auth_server",
            ),
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.1")],
        )

        # First-class check: the client is registered and the redirect URI exactly
        # matches a registered one (the authorize-time client binding). Emitted on
        # PASS too so the UI can highlight it (e.g. exact vs loose matching).
        registered = looked is not None
        redirect_ok = registered and redirect_uri in looked.redirect_uris
        reg_result = "PASS" if (registered and redirect_ok) else "FAIL"
        self.recorder.emit(
            actor="auth_server",
            phase="authorize",
            summary="Authorization server checks client registration and redirect URI.",
            detail=(
                "The server confirms the client_id is registered and that the requested "
                "redirect URI exactly matches one registered for that client, so the "
                "code can only be delivered to the client's own endpoint."
            ),
            outcome="ok" if reg_result == "PASS" else "blocked",
            check=Check(
                name="redirect_uri_registered",
                rule="client_id is registered AND redirect_uri exactly matches a registered URI",
                expected="registered client + exact redirect_uri match",
                actual="registered client + exact match"
                if reg_result == "PASS"
                else "unregistered client or redirect_uri mismatch",
                result=reg_result,
                spec_ref=SpecRef(rfc="RFC 6749", section="§3.1.2"),
            ),
            spec_refs=[SpecRef(rfc="RFC 6749", section="§3.1.2")],
        )

        # Real validation of the request.
        if response_type != "code":
            raise OAuthError("unsupported_response_type", f"response_type={response_type!r}")
        if not registered:
            raise OAuthError("unauthorized_client", f"unknown client_id {client_id!r}")
        if not redirect_ok:
            raise OAuthError("invalid_request", f"unregistered redirect_uri {redirect_uri!r}")

        # The account authenticated in this browser session is ambient (a login
        # cookie), so it comes from the trace context, defaulting to the
        # environment's user. The CSRF scenario logs in the *attacker's* own
        # account here — a genuine login for which the AS mints a valid code.
        user = trace_context.current_as_user() or self.env.user
        self.recorder.emit(
            actor="auth_server",
            phase="authorize",
            summary="User authenticates and consents to the requested scope.",
            detail=(
                f"The synthetic user '{user.username}' logs in and approves the client's "
                f"request for scope '{scope}'. No real credentials or PII are involved; "
                "the account is bundled with the tool."
            ),
            outcome="ok",
            http=HttpExchange(
                request=HttpMessage(
                    method="POST",
                    url=f"{self.env.issuer}/login",
                    body={"username": user.username, "consent": "approve", "scope": scope},
                ),
                response=HttpMessage(status=302, body={"consent": "granted"}),
                highlight=["request.body.consent"],
                source_actor="auth_server",
                target_actor="auth_server",
            ),
            knowledge_delta={
                "auth_server": KnowledgeState(has=["user_session", "consent"]),
            },
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.1")],
        )

        # Mint a single-use authorization code bound to this client + redirect URI
        # (and, when PKCE is in use, to the code_challenge).
        code = crypto.new_opaque_token(prefix="ac_")
        stored = _StoredCode(
            client_id=client_id,
            redirect_uri=redirect_uri,
            sub=user.sub,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method or ("S256" if code_challenge else None),
        )
        self._codes[code] = stored

        as_has = ["authorization_code"]
        if code_challenge is not None:
            as_has.append("code_challenge")
        issue_seq = self.recorder.emit(
            actor="auth_server",
            phase="redirect",
            summary="Authorization server redirects back with a single-use code.",
            detail=(
                "The server issues a short-lived, single-use authorization code and "
                "redirects the browser to the client's registered redirect URI, echoing "
                "the 'state' value unchanged. The code is bound server-side to this "
                "client and redirect URI; it is not itself a token."
                + (
                    " Because PKCE is in use, the server also records the code_challenge "
                    "against the code, so only the party that holds the matching "
                    "code_verifier can redeem it."
                    if code_challenge is not None
                    else ""
                )
            ),
            outcome="ok",
            # Truthful causality: the code responds to the authorization request that
            # carried the client/redirect (and, under PKCE, the challenge).
            refs=[receive_seq],
            http=HttpExchange(
                request=HttpMessage(method="GET", url=redirect_uri),
                response=HttpMessage(
                    status=302,
                    headers={"Location": f"{redirect_uri}?code={code}&state={state}"},
                    body={"code": code, "state": state},
                ),
                highlight=["response.body.code", "response.body.state"],
                source_actor="auth_server",
                target_actor="client",
            ),
            knowledge_delta={
                "auth_server": KnowledgeState(has=as_has),
            },
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.2")],
        )
        stored.issue_seq = issue_seq
        return {
            "code": code,
            "state": state,
            "redirect_uri": redirect_uri,
            "issue_seq": issue_seq,
        }

    # --- Token endpoint ----------------------------------------------------

    def token(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Redeem an authorization code for a signed access token.

        Enforces client authentication, grant type, single-use code redemption,
        redirect-URI match, and client binding, each with a first-class ``check``
        event (emitted on PASS too, so the UI can highlight them).
        """
        grant_type = request.get("grant_type")
        code = request.get("code")
        redirect_uri = request.get("redirect_uri")
        client_id = request.get("client_id")
        client_secret = request.get("client_secret")
        code_verifier = request.get("code_verifier")
        looked = self.env.client_by_id(client_id)

        # The peer that sent this request. In a REST deployment this is the
        # authenticated caller; here it is carried in the ambient trace context, so
        # the same endpoint serves the honest client and an injecting attacker
        # without the caller identity crossing the pure-protocol interface. Defaults
        # to the legitimate client, keeping the happy path unchanged.
        peer = trace_context.current_source_actor() or "client"

        request_body: Dict[str, Any] = {
            "grant_type": grant_type,
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
        }
        # A public client presents no secret at all; only show one when sent, so
        # the injection trace never references a client secret.
        if client_secret is not None:
            request_body["client_secret"] = _redact(client_secret)
        receive_highlight = ["request.body.code", "request.body.grant_type"]
        if code_verifier is not None:
            request_body["code_verifier"] = code_verifier
            # The two params that decide a code-injection attempt: the code the
            # caller holds, and the verifier it must also hold under PKCE.
            receive_highlight = ["request.body.code", "request.body.code_verifier"]

        # Keep the confidential-client wording byte-identical (the happy path uses
        # it); use accurate wording for a public client, which has no credentials.
        if looked is not None and looked.is_public:
            receive_detail = (
                "The caller presents the authorization code over the back channel to "
                "exchange it for a token. This is a public client, so there are no "
                "client credentials to present; the server will redeem the code subject "
                "to the checks that do apply."
            )
        else:
            receive_detail = (
                "The client presents the authorization code over the back channel and "
                "authenticates itself with its client credentials. The server will now "
                "verify the client, then redeem the code."
            )
        receive_seq = self.recorder.emit(
            actor="auth_server",
            phase="token",
            summary="Token endpoint receives the code exchange.",
            detail=receive_detail,
            outcome="ok",
            http=HttpExchange(
                request=HttpMessage(
                    method="POST",
                    url=self.env.token_url,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=request_body,
                ),
                response=HttpMessage(status=200, body={"processing": True}),
                highlight=receive_highlight,
                source_actor=peer,
                target_actor="auth_server",
            ),
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.3")],
        )

        if looked is not None and looked.is_public:
            # Public client (token_endpoint_auth_method=none): there is no secret to
            # verify, so client authentication is simply NOT a gate here. Recording
            # this honestly is the point — it leaves PKCE as the only binding that
            # can stop a stolen-code redemption.
            self.recorder.emit(
                actor="auth_server",
                phase="token",
                summary="Public client presents no secret (no client authentication).",
                detail=(
                    "This is a public client (a native app or SPA): it registered with "
                    "token_endpoint_auth_method=none and holds no client secret. The "
                    "token endpoint therefore performs no client authentication — a "
                    "public client_id is not a secret, so anyone can present it. Client "
                    "authentication is not a gate here; whether a captured code can be "
                    "redeemed comes down to PKCE."
                ),
                outcome="ok",
                spec_refs=[
                    SpecRef(rfc="RFC 6749", section="§2.1"),
                    SpecRef(rfc="RFC 7636", section="§1"),
                ],
            )
        else:
            # First-class client-authentication check (confidential client).
            client_auth_ok = (
                looked is not None
                and client_id == looked.client_id
                and client_secret == looked.client_secret
            )
            self.recorder.emit(
                actor="auth_server",
                phase="token",
                summary="Token endpoint authenticates the confidential client.",
                detail=(
                    "The server checks the client's credentials at the token endpoint. "
                    "Only a client that authenticates as the one the code was issued to "
                    "may redeem it over the back channel."
                ),
                outcome="ok" if client_auth_ok else "blocked",
                check=Check(
                    name="client_authentication",
                    rule="presented client_id + client_secret match the registered client",
                    expected="valid client credentials",
                    actual="authenticated" if client_auth_ok else "authentication failed",
                    result="PASS" if client_auth_ok else "FAIL",
                    spec_ref=SpecRef(rfc="RFC 6749", section="§2.3.1"),
                ),
                spec_refs=[SpecRef(rfc="RFC 6749", section="§2.3.1")],
            )
            if not client_auth_ok:
                raise OAuthError("invalid_client", "client authentication failed", status=401)
        if grant_type != "authorization_code":
            raise OAuthError("unsupported_grant_type", f"grant_type={grant_type!r}")

        stored = self._codes.get(code)

        # Truthful causality for every code-related check: it depends on where the
        # code (and its challenge) was issued and on the exchange request presenting
        # it. For an unknown code there is no issuance to anchor to.
        code_refs = [receive_seq]
        if stored is not None and stored.issue_seq is not None:
            code_refs = [stored.issue_seq, receive_seq]

        # First-class single-use check (the core auth-code safety property).
        already_used = stored is not None and stored.used
        unknown = stored is None
        check_result = "FAIL" if (already_used or unknown) else "PASS"
        single_use_seq = self.recorder.emit(
            actor="auth_server",
            phase="token",
            summary="Authorization code is redeemed exactly once.",
            detail=(
                "The server looks up the code, confirms it exists and has not been "
                "redeemed before, and marks it used. A code that is missing or already "
                "redeemed is rejected — this is what makes a captured code single-use."
            ),
            outcome="ok" if check_result == "PASS" else "blocked",
            refs=code_refs,
            check=Check(
                name="authorization_code_single_use",
                rule="code exists AND not previously redeemed",
                expected="unredeemed code",
                actual="unredeemed code" if check_result == "PASS" else "missing_or_replayed",
                result=check_result,
                spec_ref=SpecRef(rfc="RFC 6749", section="§4.1.2"),
            ),
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.2")],
        )

        if unknown:
            raise OAuthError("invalid_grant", "unknown authorization code", at_seq=single_use_seq)
        if already_used:
            raise OAuthError(
                "invalid_grant", "authorization code already redeemed", at_seq=single_use_seq
            )
        assert stored is not None

        # First-class binding check: the code is bound to the client it was issued
        # to and to the redirect URI it was requested with.
        binding_ok = stored.client_id == client_id and stored.redirect_uri == redirect_uri
        binding_seq = self.recorder.emit(
            actor="auth_server",
            phase="token",
            summary="Authorization code binding is verified (client + redirect URI).",
            detail=(
                "The server confirms the code was issued to this client and for this "
                "redirect URI. A code captured by a different client, or presented with a "
                "different redirect URI, is rejected here."
            ),
            outcome="ok" if binding_ok else "blocked",
            refs=code_refs,
            check=Check(
                name="authorization_code_binding",
                rule="stored.client_id == client_id AND stored.redirect_uri == redirect_uri",
                expected="code bound to this client and redirect_uri",
                actual="binding matches" if binding_ok else "binding mismatch",
                result="PASS" if binding_ok else "FAIL",
                spec_ref=SpecRef(rfc="RFC 6749", section="§4.1.3"),
            ),
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.3")],
        )
        if stored.client_id != client_id:
            raise OAuthError(
                "invalid_grant", "code was issued to a different client", at_seq=binding_seq
            )
        if stored.redirect_uri != redirect_uri:
            raise OAuthError("invalid_grant", "redirect_uri does not match", at_seq=binding_seq)

        # First-class PKCE check (RFC 7636 §4.6). Enforced iff the code carries a
        # challenge — i.e. PKCE was used at /authorize. This is the binding that
        # defeats auth-code injection: the redeemer must prove it holds the
        # per-request verifier, which the code alone does not reveal. The block is
        # produced by real S256 arithmetic (crypto.verify_pkce), not a scripted
        # verdict. ``last_gate_seq`` is the seq the issuance step will depend on.
        last_gate_seq = binding_seq
        if stored.code_challenge is not None:
            method = stored.code_challenge_method or "S256"
            pkce_ok = crypto.verify_pkce(code_verifier, stored.code_challenge, method)
            actual_challenge = (
                crypto.code_challenge_for(code_verifier, method)
                if code_verifier
                else "(no code_verifier presented)"
            )
            pkce_seq = self.recorder.emit(
                actor="auth_server",
                phase="token",
                summary="Token endpoint verifies the PKCE code_verifier.",
                detail=(
                    "PKCE was used to start this flow, so the code is bound to a "
                    "code_challenge. The server recomputes the challenge from the "
                    "presented code_verifier and requires it to equal the stored "
                    "code_challenge. The authorization code alone is not enough: only "
                    "the party that generated the verifier — the client instance that "
                    "began the flow — can satisfy this, so a redeemer that merely "
                    "captured the code cannot."
                ),
                outcome="ok" if pkce_ok else "blocked",
                refs=code_refs,
                check=Check(
                    name="pkce_verifier_match",
                    rule="S256(code_verifier) == code_challenge",
                    expected=stored.code_challenge,
                    actual=actual_challenge,
                    result="PASS" if pkce_ok else "FAIL",
                    spec_ref=SpecRef(rfc="RFC 7636", section="§4.6"),
                ),
                spec_refs=[SpecRef(rfc="RFC 7636", section="§4.6")],
            )
            last_gate_seq = pkce_seq
            if not pkce_ok:
                raise OAuthError(
                    "invalid_grant", "PKCE code_verifier mismatch", at_seq=pkce_seq
                )

        stored.used = True  # single-use enforcement

        # DPoP sender-constraining (RFC 9449 §5–§6): when the client presents a
        # DPoP proof with the exchange, the server verifies it and binds the token
        # to the proof's key by stamping ``cnf.jkt`` (the RFC 7638 thumbprint).
        # Absent a proof this is a no-op, so a non-DPoP exchange is byte-identical.
        extra_claims = None
        dpop_proof = request.get("dpop")
        if dpop_proof is not None:
            bound = crypto.verify_dpop_proof(
                dpop_proof, htm="POST", htu=self.env.token_url
            )
            extra_claims = {"cnf": {"jkt": bound["jkt"]}}

        access_token = crypto.sign_access_token(
            self.signing_key,
            issuer=self.env.issuer,
            subject=stored.sub,
            audience=self.env.resource_audience,
            client_id=client_id,
            scope=stored.scope,
            ttl_seconds=300,
            extra_claims=extra_claims,
        )

        self.recorder.emit(
            actor="auth_server",
            phase="token",
            summary="Authorization server issues a signed JWT access token.",
            detail=(
                "The code is valid and now spent. The server signs a real RS256 JWT "
                "access token with its private key, scoped to the resource server's "
                "audience, and returns it to the caller. The public key is available at "
                "the JWKS endpoint for verification."
            ),
            outcome="ok",
            # The token is issued only because the final gating check passed.
            refs=[last_gate_seq],
            http=HttpExchange(
                request=HttpMessage(method="POST", url=self.env.token_url),
                response=HttpMessage(
                    status=200,
                    headers={"Content-Type": "application/json"},
                    body={
                        "access_token": access_token,
                        "token_type": "Bearer",
                        "expires_in": 300,
                        "scope": stored.scope,
                    },
                ),
                highlight=["response.body.access_token", "response.body.token_type"],
                source_actor="auth_server",
                target_actor=peer,
            ),
            knowledge_delta={
                "auth_server": KnowledgeState(has=["access_token"]),
            },
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.4")],
        )
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 300,
            "scope": stored.scope,
        }


def _redact(secret: Optional[str]) -> str:
    if not secret:
        return ""
    return secret[:3] + "…" + "(redacted)"
