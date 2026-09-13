"""Phishing / smishing attack (RFC 6819) — catalog entry (roadmap)."""

from __future__ import annotations

from ..contract import SpecRef
from ..registry import attack

attack(
    id="phishing",
    label="Phishing / smishing",
    description="A fake login/consent lure harvests credentials or a code.",
    spec_ref=SpecRef(rfc="RFC 6819", section="§4.4.1.9"),
    phase=7,
    applies_to_grants=["authorization_code"],
)
