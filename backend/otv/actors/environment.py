"""Shared identities and endpoints the actors agree on.

These are the fixed facts of the sandboxed deployment: the internal hostnames,
the one registered client, the synthetic user account, and the protected
resource. They are deliberately *.internal names to make clear the whole
exchange happens between the tool's own contained actors (DESIGN.md §10/§11).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

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
class ResourceServerConfig:
    """The facts a resource server legitimately holds — and nothing more.

    Deliberately excludes the client's ``client_secret`` and the authorization
    server's registered-client table: an RS validates tokens and serves its own
    protected data, so it is given only the issuer + audience it trusts and its
    own profile store (keyed by subject). It reaches the AS's public keys through
    the ``AuthServer`` interface (a JWKS fetch in the standalone-servers future).
    """

    issuer: str
    resource_audience: str
    resource_url: str
    # The RS's own protected data: user profiles keyed by subject (``sub``). The
    # profile served is bound to the token's ``sub``, not a single ambient user.
    users_by_sub: Dict[str, SyntheticUser] = field(default_factory=dict)


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
    # Every subject the resource server can serve a profile for. Defaults to the
    # single synthetic user; later phases add an attacker-controlled account here
    # so an injected token resolves to the right (or wrong) profile.
    users: List[SyntheticUser] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.users:
            self.users = [self.user]

    def resource_server_config(self) -> ResourceServerConfig:
        """The role-scoped facts handed to the resource server (see B2)."""
        return ResourceServerConfig(
            issuer=self.issuer,
            resource_audience=self.resource_audience,
            resource_url=self.resource_url,
            users_by_sub={u.sub: u for u in self.users},
        )
