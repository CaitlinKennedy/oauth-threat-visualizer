"""Auth-code injection attack (RFC 9700 §4.5) — self-registering catalog entry."""

from __future__ import annotations

from ..contract import SpecRef
from ..registry import attack

attack(
    id="auth_code_injection",
    label="Auth-code injection",
    description="Inject an attacker-obtained code into a victim's session.",
    spec_ref=SpecRef(rfc="RFC 9700", section="§4.5"),
    phase=1,
    applies_to_grants=["authorization_code"],
    incompatibilities=[],
)
