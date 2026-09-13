"""Shared identities and endpoints the actors agree on.

These are the fixed facts of the sandboxed deployment: the internal hostnames,
the one registered client, the synthetic user account, and the protected
resource. They are deliberately *.internal names to make clear the whole
exchange happens between the tool's own contained actors (DESIGN.md §10/§11).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

ISSUER = "https://auth.oauthlab.internal"
AUTHORIZE_URL = f"{ISSUER}/oauth/authorize"
TOKEN_URL = f"{ISSUER}/oauth/token"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"

RESOURCE_AUDIENCE = "https://api.oauthlab.internal"
RESOURCE_URL = f"{RESOURCE_AUDIENCE}/userinfo"


@dataclass
class RegisteredClient:
    client_id: str = "demo-web-app"
    # A confidential client (RFC 6749 §2.1): it authenticates at the token
    # endpoint with a secret over the back channel (RFC 6749 §2.3.1 / §4.1.3).
    client_secret: str = "s3cr3t-demo-web-app-01HXZ"
    redirect_uris: List[str] = field(
        default_factory=lambda: ["https://app.oauthlab.internal/callback"]
    )
    scope: str = "profile email"

    @property
    def redirect_uri(self) -> str:
        return self.redirect_uris[0]


@dataclass
class SyntheticUser:
    """A bundled, non-real account — there is no real PII in the tool."""

    sub: str = "user-8f31c2"
    username: str = "avery"
    display_name: str = "Avery Diaz"
    email: str = "avery@oauthlab.internal"


@dataclass
class Environment:
    issuer: str = ISSUER
    authorize_url: str = AUTHORIZE_URL
    token_url: str = TOKEN_URL
    jwks_url: str = JWKS_URL
    resource_url: str = RESOURCE_URL
    resource_audience: str = RESOURCE_AUDIENCE
    client: RegisteredClient = field(default_factory=RegisteredClient)
    user: SyntheticUser = field(default_factory=SyntheticUser)
