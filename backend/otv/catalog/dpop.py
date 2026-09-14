"""DPoP capability (RFC 9449) — self-registering catalog entry.

Sender-constrained (proof-of-possession) tokens: the client holds a DPoP key, the
issued token is bound to that key via ``cnf.jkt`` (the RFC 7638 JWK thumbprint),
and every protected-resource call carries a real DPoP proof JWT the resource
server verifies. This is the token-level sibling of key-based client
authentication: the token is bound to a key the bearer must prove it holds, so a
stolen token is inert without the matching private key.
"""

from __future__ import annotations

from ..contract import SpecRef
from ..registry import capability

capability(
    id="dpop",
    label="DPoP",
    description="Sender-constrain the token to a proof-of-possession key (cnf.jkt).",
    spec_ref=SpecRef(rfc="RFC 9449", section="§4"),
    order=50,
    # Sender-constraining applies to any grant that yields a token.
    applies_to_grants=[],
    # The first-class check this capability's own enforcement emits — the resource
    # server's key-binding verification (see engine.runners.support.
    # CHECK_TO_CAPABILITY, derived by scanning this).
    check_names=["dpop_binding"],
)
