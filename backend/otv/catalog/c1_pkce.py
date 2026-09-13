"""PKCE capability (RFC 7636) — self-registering catalog entry."""

from __future__ import annotations

from ..contract import SpecRef
from ..registry import ParamSpec, capability

capability(
    id="pkce",
    label="PKCE",
    description="Bind the authorization code to a per-request verifier (S256).",
    spec_ref=SpecRef(rfc="RFC 7636", section="§4"),
    phase=1,
    applies_to_grants=["authorization_code"],
    # The first-class check this capability's own enforcement emits (see
    # engine.runners.support.CHECK_TO_CAPABILITY, derived by scanning this).
    check_names=["pkce_verifier_match"],
    params=[
        ParamSpec(
            name="method",
            type="enum",
            default="S256",
            description="Code challenge method.",
            choices=["S256", "plain"],
        )
    ],
)
