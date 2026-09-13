"""Static-secret leak attack (RFC 6749 §10.3) — catalog entry (roadmap)."""

from __future__ import annotations

from ..contract import SpecRef
from ..registry import attack

attack(
    id="static_secret_leak",
    label="Static-secret leak",
    description="A never-rotating client secret is captured and reused.",
    spec_ref=SpecRef(rfc="RFC 6749", section="§10.3"),
    phase=5,
    applies_to_grants=["client_credentials"],
)
