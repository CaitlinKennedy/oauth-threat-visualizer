"""DPoP capability (RFC 9449) — self-registering catalog entry (roadmap)."""

from __future__ import annotations

from ..contract import SpecRef
from ..registry import capability

capability(
    id="dpop",
    label="DPoP",
    description="Sender-constrained tokens via a proof-of-possession key.",
    spec_ref=SpecRef(rfc="RFC 9449", section="§4"),
    phase=6,
    # Sender-constraining applies to any grant that yields a token.
    applies_to_grants=[],
)
