"""Client-authentication method capability (RFC 6749 §2.3 / RFC 7523 §2.2).

How a *confidential* client proves its identity to the token endpoint. This is
orthogonal to the grant (it applies to the client-credentials grant and to the
authorization-code grant alike), so it is modeled as a capability with a single
``method`` parameter rather than as a grant:

- ``client_secret_basic`` — the client id + secret in an HTTP ``Authorization:
  Basic`` header (RFC 6749 §2.3.1). A shared *static* secret.
- ``client_secret_post`` — the same shared secret, carried in the request body
  (RFC 6749 §2.3.1). Still a static secret; it merely rides in a different field.
- ``private_key_jwt`` — a short-lived, ``jti``-carrying ``client_assertion`` the
  client signs with a private key (RFC 7523 §2.2 / RFC 7521 §4.2). The
  authorization server holds only the matching *public* key, so nothing that
  transits the wire can be replayed to impersonate the client.

The teaching contrast (DESIGN.md §4/§5): a static secret that never rotates is
permanent impersonation once leaked, whereas the key-based assertion binds client
identity to a private key + a time window + a one-time ``jti`` — the same
key-vs-secret binding this tool's thesis keeps returning to.
"""

from __future__ import annotations

from ..contract import SpecRef
from ..registry import ParamSpec, capability

capability(
    id="client_auth",
    label="Client authentication method",
    description=(
        "How the client authenticates to the token endpoint: a shared static "
        "secret (Basic header or POST body) or a signed private_key_jwt assertion."
    ),
    spec_ref=SpecRef(rfc="RFC 6749", section="§2.3"),
    order=40,
    # Client authentication is not tied to one grant: it gates the token endpoint
    # for the client-credentials grant and for the confidential authorization-code
    # exchange too, so it applies broadly.
    applies_to_grants=[],
    # The first-class checks this capability's own enforcement emits, one per
    # family of method. Attribution (support.CHECK_TO_CAPABILITY) is derived by
    # scanning this, so a block at either check resolves back to ``client_auth``.
    check_names=["client_secret_auth", "private_key_jwt_auth"],
    params=[
        ParamSpec(
            name="method",
            type="enum",
            default="client_secret_basic",
            description="Client authentication method presented at the token endpoint.",
            choices=["client_secret_basic", "client_secret_post", "private_key_jwt"],
        )
    ],
)
