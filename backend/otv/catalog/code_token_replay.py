"""Auth-code / token replay attack (RFC 6819) — self-registering catalog entry.

The auth-code replay is exercised end to end: the honest client completes a
redemption, then the attacker replays the same code and the single-use code
store rejects the second attempt (RFC 6749 §4.1.2).
"""

from __future__ import annotations

from ..contract import SpecRef
from ..registry import attack

attack(
    id="code_token_replay",
    label="Auth-code / token replay",
    description="Reuse a captured code or token a second time.",
    spec_ref=SpecRef(rfc="RFC 6819", section="§4.4.1.1"),
    order=20,
    # Code replay is auth-code-specific; token replay applies to any grant, so
    # this item is not restricted to a single grant.
    applies_to_grants=[],
)
