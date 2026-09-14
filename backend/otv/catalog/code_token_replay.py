"""Auth-code replay attack (RFC 6819) — self-registering catalog entry.

The auth-code replay is exercised end to end: the honest client completes a
redemption, then the attacker replays the same code and the single-use code
store rejects the second attempt (RFC 6749 §4.1.2).
"""

from __future__ import annotations

from ..contract import SpecRef
from ..registry import attack

attack(
    id="code_token_replay",
    label="Auth-code replay (token endpoint)",
    description="Redeem a captured authorization code a second time.",
    spec_ref=SpecRef(rfc="RFC 6819", section="§4.4.1.1"),
    order=20,
    # Replays a single-use authorization code, which only this grant issues.
    applies_to_grants=["authorization_code"],
)
