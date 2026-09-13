"""Chained phishing-then-inject attack (RFC 9700) — catalog entry (roadmap)."""

from __future__ import annotations

from ..contract import SpecRef
from ..registry import attack

attack(
    id="phish_then_inject",
    label="Chained: phish then inject",
    description="Phishing harvests a detail that enables auth-code injection.",
    spec_ref=SpecRef(rfc="RFC 9700", section="§4"),
    phase=7,
    applies_to_grants=["authorization_code"],
)
