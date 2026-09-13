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
from typing import Any, Dict, List, Optional

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
    def authorize(
        self, params: Dict[str, Any], *, on_behalf_of: str, refs: List[int]
    ) -> Dict[str, Any]:
        """Handle an authorization request (``GET /oauth/authorize``).

        Validates the client and redirect URI, authenticates the user, records
        consent, and mints a single-use code. Returns
        ``{"code": ..., "state": ..., "redirect_uri": ...}``.
        """

    @abc.abstractmethod
    def token(
        self, params: Dict[str, Any], *, on_behalf_of: str, refs: List[int]
    ) -> Dict[str, Any]:
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

    def authorize(
        self, params: Dict[str, Any], *, on_behalf_of: str, refs: List[int]
    ) -> Dict[str, Any]:
        """Handle an authorization request and return the redirect parameters.

        Emits: receive request, authenticate + consent, issue code.
        """
        client = self.env.client
        response_type = params.get("response_type")
        client_id = params.get("client_id")
        redirect_uri = params.get("redirect_uri")
        scope = params.get("scope", client.scope)
        state = params.get("state")

        recv_seq = self.recorder.emit(
            actor="auth_server",
            on_behalf_of=on_behalf_of,
            phase="authorize",
            summary="Authorization server receives the authorization request.",
            detail=(
                "The user's browser arrives at the authorization endpoint carrying the "
                "client's request. The server checks that the client is registered, that "
                "the redirect URI exactly matches one it registered, and that the "
                "response type is 'code' for the authorization-code grant."
            ),
            outcome="ok",
            refs=refs,
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
                highlight=["client_id", "redirect_uri", "response_type"],
            ),
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.1")],
        )

        # Real validation of the request.
        if response_type != "code":
            raise OAuthError("unsupported_response_type", f"response_type={response_type!r}")
        if client_id != client.client_id:
            raise OAuthError("unauthorized_client", f"unknown client_id {client_id!r}")
        if redirect_uri not in client.redirect_uris:
            raise OAuthError("invalid_request", f"unregistered redirect_uri {redirect_uri!r}")

        user = self.env.user
        auth_seq = self.recorder.emit(
            actor="auth_server",
            on_behalf_of=on_behalf_of,
            phase="authorize",
            summary="User authenticates and consents to the requested scope.",
            detail=(
                f"The synthetic user '{user.username}' logs in and approves the client's "
                f"request for scope '{scope}'. No real credentials or PII are involved; "
                "the account is bundled with the tool."
            ),
            outcome="ok",
            refs=[recv_seq],
            http=HttpExchange(
                request=HttpMessage(
                    method="POST",
                    url=f"{self.env.issuer}/login",
                    body={"username": user.username, "consent": "approve", "scope": scope},
                ),
                response=HttpMessage(status=302, body={"consent": "granted"}),
                highlight=["consent"],
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
            on_behalf_of=on_behalf_of,
            phase="redirect",
            summary="Authorization server redirects back with a single-use code.",
            detail=(
                "The server issues a short-lived, single-use authorization code and "
                "redirects the browser to the client's registered redirect URI, echoing "
                "the 'state' value unchanged. The code is bound server-side to this "
                "client and redirect URI; it is not itself a token."
            ),
            outcome="ok",
            refs=[auth_seq],
            http=HttpExchange(
                request=HttpMessage(method="GET", url=redirect_uri),
                response=HttpMessage(
                    status=302,
                    headers={"Location": f"{redirect_uri}?code={code}&state={state}"},
                    body={"code": code, "state": state},
                ),
                highlight=["code", "state"],
            ),
            knowledge_delta={
                "auth_server": KnowledgeState(has=["authorization_code"]),
            },
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.2")],
        )
        return {"code": code, "state": state, "redirect_uri": redirect_uri}

    # --- Token endpoint ----------------------------------------------------

    def token(
        self, params: Dict[str, Any], *, on_behalf_of: str, refs: List[int]
    ) -> Dict[str, Any]:
        """Redeem an authorization code for a signed access token.

        Enforces client authentication, grant type, single-use code redemption,
        redirect-URI match, and client binding. Emits a first-class ``check``
        event for single-use enforcement.
        """
        client = self.env.client
        grant_type = params.get("grant_type")
        code = params.get("code")
        redirect_uri = params.get("redirect_uri")
        client_id = params.get("client_id")
        client_secret = params.get("client_secret")

        recv_seq = self.recorder.emit(
            actor="auth_server",
            on_behalf_of=on_behalf_of,
            phase="token",
            summary="Token endpoint receives the code exchange.",
            detail=(
                "The client presents the authorization code over the back channel and "
                "authenticates itself with its client credentials. The server will now "
                "verify the client, then redeem the code."
            ),
            outcome="ok",
            refs=refs,
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
                highlight=["code", "grant_type"],
            ),
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.3")],
        )

        # Client authentication (confidential client).
        if client_id != client.client_id or client_secret != client.client_secret:
            raise OAuthError("invalid_client", "client authentication failed", status=401)
        if grant_type != "authorization_code":
            raise OAuthError("unsupported_grant_type", f"grant_type={grant_type!r}")

        stored = self._codes.get(code)

        # First-class single-use check (the core auth-code safety property).
        already_used = stored is not None and stored.used
        unknown = stored is None
        check_result = "FAIL" if (already_used or unknown) else "PASS"
        check_seq = self.recorder.emit(
            actor="auth_server",
            on_behalf_of=on_behalf_of,
            phase="token",
            summary="Authorization code is redeemed exactly once.",
            detail=(
                "The server looks up the code, confirms it exists and has not been "
                "redeemed before, and marks it used. A code that is missing or already "
                "redeemed is rejected — this is what makes a captured code single-use."
            ),
            outcome="ok" if check_result == "PASS" else "blocked",
            refs=[recv_seq],
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
            on_behalf_of=on_behalf_of,
            phase="token",
            summary="Authorization server issues a signed JWT access token.",
            detail=(
                "The code is valid and now spent. The server signs a real RS256 JWT "
                "access token with its private key, scoped to the resource server's "
                "audience, and returns it to the client. The public key is available at "
                "the JWKS endpoint for verification."
            ),
            outcome="ok",
            refs=[check_seq],
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
                highlight=["access_token", "token_type"],
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
