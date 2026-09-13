"""AS Issuer Identification capability (RFC 9207) — catalog entry (roadmap)."""

from __future__ import annotations

from ..contract import SpecRef
from ..registry import capability

capability(
    id="issuer_id",
    label="AS Issuer Identification",
    description="The AS returns its iss in the authorization response (mix-up defense).",
    spec_ref=SpecRef(rfc="RFC 9207", section="§2"),
    phase=7,
    applies_to_grants=["authorization_code"],
)
