"""The Resource Server.

Protects an API endpoint and validates the access token before serving the
resource. Phase 0 validates the JWT's signature (against the AS's published
JWKS), expiry, issuer, and audience. This is the place where, in later phases, a
stolen-but-unbound token visibly fails; here, on the happy path, a valid token
succeeds.
"""

from __future__ import annotations

import abc
from typing import Any, Dict, List

import jwt

from .. import crypto
from ..contract import Check, HttpExchange, HttpMessage, KnowledgeState, SpecRef
from ..recorder import Recorder
from .auth_server import AuthServer
from .environment import Environment


class ResourceServer(abc.ABC):
    """Service-API interface for the resource server."""

    @abc.abstractmethod
    def get_resource(
        self, request: Dict[str, Any], *, refs: List[int], on_behalf_of: str = "user"
    ) -> Dict[str, Any]:
        """Validate the bearer token and return the protected resource.

        Verifies the JWT (signature via the AS's JWKS, plus exp/iss/aud) and,
        only if it passes, returns the resource. Returns
        ``{"ok": bool, "resource": {...} | None, "seq": int}``.
        """


class ResourceServerImpl(ResourceServer):
    def __init__(self, recorder: Recorder, env: Environment, auth_server: AuthServer):
        self.recorder = recorder
        self.env = env
        # The RS trusts the AS's public keys, obtained via the AS interface's
        # jwks() (a JWKS fetch in the standalone-servers future).
        self._auth_server = auth_server

    def get_resource(
        self, request: Dict[str, Any], *, refs: List[int], on_behalf_of: str = "user"
    ) -> Dict[str, Any]:
        auth_header = request.get("headers", {}).get("Authorization", "")
        token = auth_header[len("Bearer ") :] if auth_header.startswith("Bearer ") else ""

        jwks = self._auth_server.jwks()
        valid = True
        failure = None
        claims: Dict[str, Any] = {}
        try:
            claims = crypto.verify_access_token(
                token,
                jwks=jwks,
                issuer=self.env.issuer,
                audience=self.env.resource_audience,
            )
        except jwt.PyJWTError as exc:  # signature/exp/iss/aud failures
            valid = False
            failure = type(exc).__name__

        check_seq = self.recorder.emit(
            actor="resource_server",
            on_behalf_of=on_behalf_of,
            phase="resource",
            summary="Resource server validates the access token.",
            detail=(
                "The resource server verifies the JWT's signature against the "
                "authorization server's published JWKS and checks the expiry, issuer, "
                "and audience. Only a token that passes every check is honored."
            ),
            outcome="ok" if valid else "blocked",
            refs=refs,
            http=HttpExchange(
                request=HttpMessage(
                    method="GET",
                    url=self.env.resource_url,
                    headers={"Authorization": "Bearer <access_token>"},
                ),
                response=HttpMessage(
                    status=200 if valid else 401,
                    body={"validated": valid} if valid else {"error": "invalid_token"},
                ),
                highlight=["Authorization"],
            ),
            check=Check(
                name="access_token_validation",
                rule="verify JWS signature via JWKS AND check exp/iss/aud",
                expected="valid signature, unexpired, aud=resource server",
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

        user = self.env.user
        resource = {
            "sub": claims.get("sub"),
            "username": user.username,
            "name": user.display_name,
            "email": user.email,
            "scope": claims.get("scope"),
        }
        serve_seq = self.recorder.emit(
            actor="resource_server",
            on_behalf_of=on_behalf_of,
            phase="resource",
            summary="Resource server returns the protected resource.",
            detail=(
                "Token validated. The resource server returns the protected profile "
                "resource for the subject named in the token, completing the flow: the "
                "user has authorized the client and the client has accessed the API."
            ),
            outcome="ok",
            refs=[check_seq],
            http=HttpExchange(
                request=HttpMessage(method="GET", url=self.env.resource_url),
                response=HttpMessage(
                    status=200,
                    headers={"Content-Type": "application/json"},
                    body=resource,
                ),
                highlight=["sub", "scope"],
            ),
            spec_refs=[SpecRef(rfc="RFC 6749", section="§7")],
        )
        return {"ok": True, "resource": resource, "seq": serve_seq}
