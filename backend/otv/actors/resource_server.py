"""The Resource Server.

Protects an API endpoint and validates the access token before serving the
resource. Phase 0 validates the JWT's signature (against the AS's published
JWKS), expiry, issuer, audience, and ``typ``. This is the place where, in later
phases, a stolen-but-unbound token visibly fails; here, on the happy path, a
valid token succeeds.

The service-API interface is pure protocol: ``get_resource(request)`` takes only
the domain request. Correlation metadata (``on_behalf_of``, causal ``refs``) is
captured out-of-band via the ambient trace context, not passed across the seam.
"""

from __future__ import annotations

import abc
from typing import Any, Dict, Optional

import jwt

from .. import crypto, trace_context
from ..contract import Check, HttpExchange, HttpMessage, KnowledgeState, SpecRef
from ..recorder import Recorder
from .auth_server import AuthServer
from .environment import ResourceServerConfig


class ResourceServer(abc.ABC):
    """Service-API interface for the resource server."""

    @abc.abstractmethod
    def get_resource(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Validate the bearer token and return the protected resource.

        Verifies the JWT (signature via the AS's JWKS, plus exp/iss/aud/typ) and,
        only if it passes, looks up and returns the profile bound to the token's
        subject. Returns ``{"ok": bool, "resource": {...} | None, "seq": int}``.
        """


class ResourceServerImpl(ResourceServer):
    def __init__(
        self, recorder: Recorder, config: ResourceServerConfig, auth_server: AuthServer
    ):
        self.recorder = recorder
        self.config = config
        # The RS trusts the AS's public keys, obtained via the AS interface's
        # jwks() (a JWKS fetch in the standalone-servers future). It is given no
        # client secret and no registered-client table (see B2).
        self._auth_server = auth_server

    def get_resource(self, request: Dict[str, Any]) -> Dict[str, Any]:
        auth_header = request.get("headers", {}).get("Authorization", "")
        token = auth_header[len("Bearer ") :] if auth_header.startswith("Bearer ") else ""

        # The peer presenting the token (ambient request scope). Defaults to the
        # legitimate client so the happy path is unchanged; an attacker replaying a
        # stolen token is attributed to the attacker lane.
        peer = trace_context.current_source_actor() or "client"

        jwks = self._auth_server.jwks()
        valid = True
        failure = None
        claims: Dict[str, Any] = {}
        try:
            claims = crypto.verify_access_token(
                token,
                jwks=jwks,
                issuer=self.config.issuer,
                audience=self.config.resource_audience,
            )
        except jwt.PyJWTError as exc:  # signature/exp/iss/aud/typ failures
            valid = False
            failure = type(exc).__name__

        check_seq = self.recorder.emit(
            actor="resource_server",
            phase="resource",
            summary="Resource server validates the access token.",
            detail=(
                "The resource server verifies the JWT's signature against the "
                "authorization server's published JWKS and checks the expiry, issuer, "
                "audience, and token type (typ=at+jwt). Only a token that passes every "
                "check is honored."
            ),
            outcome="ok" if valid else "blocked",
            http=HttpExchange(
                request=HttpMessage(
                    method="GET",
                    url=self.config.resource_url,
                    headers={"Authorization": "Bearer <access_token>"},
                ),
                response=HttpMessage(
                    status=200 if valid else 401,
                    body={"validated": valid} if valid else {"error": "invalid_token"},
                ),
                highlight=["request.headers.Authorization"],
                source_actor=peer,
                target_actor="resource_server",
            ),
            check=Check(
                name="access_token_validation",
                rule="verify JWS signature via JWKS AND check exp/iss/aud/typ",
                expected="valid signature, unexpired, aud=resource server, typ=at+jwt",
                actual="all checks passed" if valid else f"rejected ({failure})",
                result="PASS" if valid else "FAIL",
                spec_ref=SpecRef(rfc="RFC 9068", section="§4"),
            ),
            knowledge_delta={
                "resource_server": KnowledgeState(has=["verified_token_claims"])
                if valid
                else KnowledgeState(),
            },
            spec_refs=[
                SpecRef(rfc="RFC 6749", section="§7"),
                SpecRef(rfc="RFC 9068", section="§4"),
            ],
        )

        if not valid:
            return {"ok": False, "resource": None, "seq": check_seq}

        # Bind the response to the token's subject: look up that user's profile in
        # the RS's own store. A token whose sub the RS does not recognize gets a
        # 404 — the resource is tied to the token, not to a single ambient user.
        sub = claims.get("sub")
        profile = self._lookup_user(sub)
        if profile is None:
            miss_seq = self.recorder.emit(
                actor="resource_server",
                phase="resource",
                summary="Resource server has no profile for the token's subject.",
                detail=(
                    "The token verified, but its 'sub' does not correspond to any "
                    "account the resource server serves, so there is nothing to return. "
                    "The response is bound to the subject named in the token."
                ),
                outcome="blocked",
                http=HttpExchange(
                    request=HttpMessage(method="GET", url=self.config.resource_url),
                    response=HttpMessage(
                        status=404, body={"error": "not_found", "sub": sub}
                    ),
                    highlight=["response.body.sub"],
                    source_actor="resource_server",
                    target_actor=peer,
                ),
                spec_refs=[SpecRef(rfc="RFC 6749", section="§7")],
            )
            return {"ok": False, "resource": None, "seq": miss_seq}

        resource = {
            "sub": claims.get("sub"),
            "username": profile.username,
            "name": profile.display_name,
            "email": profile.email,
            "scope": claims.get("scope"),
        }
        serve_seq = self.recorder.emit(
            actor="resource_server",
            phase="resource",
            summary="Resource server returns the protected resource.",
            detail=(
                "Token validated. The resource server returns the protected profile "
                "resource for the subject named in the token, completing the flow: the "
                "user has authorized the client and the client has accessed the API."
            ),
            outcome="ok",
            http=HttpExchange(
                request=HttpMessage(method="GET", url=self.config.resource_url),
                response=HttpMessage(
                    status=200,
                    headers={"Content-Type": "application/json"},
                    body=resource,
                ),
                highlight=["response.body.sub", "response.body.scope"],
                source_actor="resource_server",
                target_actor=peer,
            ),
            spec_refs=[SpecRef(rfc="RFC 6749", section="§7")],
        )
        return {"ok": True, "resource": resource, "seq": serve_seq}

    def _lookup_user(self, sub: Optional[str]):
        if sub is None:
            return None
        return self.config.users_by_sub.get(sub)
