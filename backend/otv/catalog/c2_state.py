"""``state`` capability (RFC 6749 §10.12) — self-registering catalog entry.

Binds the authorization response to the user's session: the client generates a
``state`` on /authorize and verifies it on the redirect. When active, a
mismatched or absent ``state`` is rejected (anti-CSRF); when inactive, the client
reports the mismatch honestly but does not enforce it.
"""

from __future__ import annotations

from ..contract import SpecRef
from ..registry import capability

capability(
    id="state",
    label="state parameter",
    description="Bind the response to the user's session (anti-CSRF).",
    spec_ref=SpecRef(rfc="RFC 6749", section="§10.12"),
    phase=2,
    applies_to_grants=["authorization_code"],
)
