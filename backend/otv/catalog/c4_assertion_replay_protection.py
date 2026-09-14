"""Assertion replay protection capability (RFC 7523) — self-registering entry.

The JWT bearer grant has no front channel: a signed assertion is presented
directly to the token endpoint. The trust therefore relocates onto the assertion
itself, and the residual attack is **assertion replay** — re-presenting a captured
but still-valid assertion. This capability is the mitigation: the token endpoint
enforces one-time use of each assertion's ``jti`` (paired with the assertion's own
short ``exp`` and its ``aud`` = the token endpoint). When active, a replayed
assertion whose ``jti`` has already been seen is rejected; when inactive, the
server can still observe the reused ``jti`` but does not act on it, so the replay
is honored (the honest-report behaviour the flow-2 preset shows).

Modelling it as a toggleable capability (rather than folding it into the grant)
is deliberate: it gives a clean flow-2 vs flow-3 paired diff that diverges at
exactly one step — the ``jti`` check on the replay.
"""

from __future__ import annotations

from ..contract import SpecRef
from ..registry import capability

capability(
    id="assertion_replay_protection",
    label="Assertion replay protection",
    description="Enforce one-time use of an assertion's jti (with short exp + aud binding).",
    spec_ref=SpecRef(rfc="RFC 7523", section="§3"),
    phase=4,
    applies_to_grants=["jwt_bearer"],
    # The first-class check this capability's own enforcement emits (see
    # engine.runners.support.CHECK_TO_CAPABILITY, derived by scanning this).
    check_names=["assertion_jti_single_use"],
)
