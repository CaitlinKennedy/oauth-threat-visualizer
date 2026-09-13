"""The IdP / Authorization Server.

Hand-rolled OAuth 2.0 authorization-code endpoints on real primitives so every
protocol step and check is ours to instrument. Phase 0 implements:

- ``/oauth/authorize`` — validates the client, authenticates the (synthetic)
  user, records consent, and mints a **single-use** authorization code bound to
  the client and redirect URI.
- ``/oauth/token`` — authenticates the confidential client, redeems the code
  (enforcing single use, redirect-URI match, and client binding), and signs a
  **real** RS256 JWT access token.
- ``/.well-known/jwks.json`` — publishes the public signing key.

PKCE, DPoP, issuer identification, and introspection arrive in later phases.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .. import crypto
from ..contract import Check, HttpExchange, HttpMessage, KnowledgeState, SpecRef
from ..recorder import Recorder
from .environment import Environment


class OAuthError(Exception):
    """An OAuth protocol error (maps to an error response at an endpoint)."""

    def __init__(self, error: str, description: str, status: int = 400):
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description
        self.status = status


@dataclass
class _StoredCode:
    client_id: str
    redirect_uri: str
    sub: str
    scope: str
    used: bool = False


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
        client = self.env.client
        response_type = params.get("response_type")
        client_id = params.get("client_id")
        redirect_uri = params.get("redirect_uri")
        scope = params.get("scope", client.scope)
        state = params.get("state")

        self.recorder.emit(
            actor="auth_server",
            phase="authorize",
            summary="Authorization server receives the authorization request.",
            detail=(
                "The user's browser arrives at the authorization endpoint carrying the "
                "client's request. The server checks that the client is registered, that "
                "the redirect URI exactly matches one it registered, and that the "
                "response type is 'code' for the authorization-code grant."
            ),
            outcome="ok",
            http=HttpExchange(
                request=HttpMessage(
                    method="GET",
                    url=self.env.authorize_url,
                    headers={"Host": "auth.oauthlab.internal"},
                    body={
                        "response_type": response_type,
                        "client_id": client_id,
                        "redirect_uri": redirect_uri,
                        "scope": scope,
                        "state": state,
                    },
                ),
                response=HttpMessage(status=200, body={"page": "login_and_consent"}),
                highlight=[
                    "request.body.client_id",
                    "request.body.redirect_uri",
                    "request.body.response_type",
                ],
                source_actor="client",
                target_actor="auth_server",
            ),
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.1")],
        )

        # First-class check: the client is registered and the redirect URI exactly
        # matches a registered one (the authorize-time client binding). Emitted on
        # PASS too so later phases can highlight it (e.g. exact vs loose matching).
        registered = client_id == client.client_id
        redirect_ok = redirect_uri in client.redirect_uris
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

        user = self.env.user
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

        # Mint a single-use authorization code bound to this client + redirect URI.
        code = crypto.new_opaque_token(prefix="ac_")
        self._codes[code] = _StoredCode(
            client_id=client_id,
            redirect_uri=redirect_uri,
            sub=user.sub,
            scope=scope,
        )

        self.recorder.emit(
            actor="auth_server",
            phase="redirect",
            summary="Authorization server redirects back with a single-use code.",
            detail=(
                "The server issues a short-lived, single-use authorization code and "
                "redirects the browser to the client's registered redirect URI, echoing "
                "the 'state' value unchanged. The code is bound server-side to this "
                "client and redirect URI; it is not itself a token."
            ),
            outcome="ok",
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
                "auth_server": KnowledgeState(has=["authorization_code"]),
            },
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.2")],
        )
        return {"code": code, "state": state, "redirect_uri": redirect_uri}

    # --- Token endpoint ----------------------------------------------------

    def token(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Redeem an authorization code for a signed access token.

        Enforces client authentication, grant type, single-use code redemption,
        redirect-URI match, and client binding, each with a first-class ``check``
        event (emitted on PASS too, so later phases can highlight them).
        """
        client = self.env.client
        grant_type = request.get("grant_type")
        code = request.get("code")
        redirect_uri = request.get("redirect_uri")
        client_id = request.get("client_id")
        client_secret = request.get("client_secret")

        self.recorder.emit(
            actor="auth_server",
            phase="token",
            summary="Token endpoint receives the code exchange.",
            detail=(
                "The client presents the authorization code over the back channel and "
                "authenticates itself with its client credentials. The server will now "
                "verify the client, then redeem the code."
            ),
            outcome="ok",
            http=HttpExchange(
                request=HttpMessage(
                    method="POST",
                    url=self.env.token_url,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body={
                        "grant_type": grant_type,
                        "code": code,
                        "redirect_uri": redirect_uri,
                        "client_id": client_id,
                        "client_secret": _redact(client_secret),
                    },
                ),
                response=HttpMessage(status=200, body={"processing": True}),
                highlight=["request.body.code", "request.body.grant_type"],
                source_actor="client",
                target_actor="auth_server",
            ),
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.3")],
        )

        # First-class client-authentication check (confidential client).
        client_auth_ok = client_id == client.client_id and client_secret == client.client_secret
        self.recorder.emit(
            actor="auth_server",
            phase="token",
            summary="Token endpoint authenticates the confidential client.",
            detail=(
                "The server checks the client's credentials at the token endpoint. Only "
                "a client that authenticates as the one the code was issued to may redeem "
                "it over the back channel."
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

        # First-class single-use check (the core auth-code safety property).
        already_used = stored is not None and stored.used
        unknown = stored is None
        check_result = "FAIL" if (already_used or unknown) else "PASS"
        self.recorder.emit(
            actor="auth_server",
            phase="token",
            summary="Authorization code is redeemed exactly once.",
            detail=(
                "The server looks up the code, confirms it exists and has not been "
                "redeemed before, and marks it used. A code that is missing or already "
                "redeemed is rejected — this is what makes a captured code single-use."
            ),
            outcome="ok" if check_result == "PASS" else "blocked",
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
            raise OAuthError("invalid_grant", "unknown authorization code")
        if already_used:
            raise OAuthError("invalid_grant", "authorization code already redeemed")
        assert stored is not None

        # First-class binding check: the code is bound to the client it was issued
        # to and to the redirect URI it was requested with.
        binding_ok = stored.client_id == client_id and stored.redirect_uri == redirect_uri
        self.recorder.emit(
            actor="auth_server",
            phase="token",
            summary="Authorization code binding is verified (client + redirect URI).",
            detail=(
                "The server confirms the code was issued to this client and for this "
                "redirect URI. A code captured by a different client, or presented with a "
                "different redirect URI, is rejected here."
            ),
            outcome="ok" if binding_ok else "blocked",
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
            raise OAuthError("invalid_grant", "code was issued to a different client")
        if stored.redirect_uri != redirect_uri:
            raise OAuthError("invalid_grant", "redirect_uri does not match")

        stored.used = True  # single-use enforcement

        access_token = crypto.sign_access_token(
            self.signing_key,
            issuer=self.env.issuer,
            subject=stored.sub,
            audience=self.env.resource_audience,
            client_id=client_id,
            scope=stored.scope,
            ttl_seconds=300,
        )

        self.recorder.emit(
            actor="auth_server",
            phase="token",
            summary="Authorization server issues a signed JWT access token.",
            detail=(
                "The code is valid and now spent. The server signs a real RS256 JWT "
                "access token with its private key, scoped to the resource server's "
                "audience, and returns it to the client. The public key is available at "
                "the JWKS endpoint for verification."
            ),
            outcome="ok",
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
                target_actor="client",
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
