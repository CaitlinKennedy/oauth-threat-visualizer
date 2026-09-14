"""Assertion replay attack (RFC 7523) — self-registering catalog entry.

The JWT bearer grant removes the front channel, so the front-channel attacks
(auth-code injection/interception, redirect CSRF, mix-up) simply do not apply.
The counter-lesson is that the trust relocates onto the signing key + assertion:
an attacker who captures a still-valid assertion (e.g. from a proxy/log leak on
the back channel) can **replay** it at the token endpoint. What the attacker
cannot do is mint a *fresh* assertion — it lacks the issuer's signing key — so the
replay is defeated by one-time ``jti`` use, short ``exp``, and the ``aud`` binding
(the ``assertion_replay_protection`` capability).
"""

from __future__ import annotations

from ..contract import SpecRef
from ..registry import attack

attack(
    id="assertion_replay",
    label="Assertion replay",
    description="Capture a valid JWT assertion and re-present it at the token endpoint.",
    spec_ref=SpecRef(rfc="RFC 7523", section="§3"),
    order=40,
    # Assertion replay is specific to the JWT bearer grant (RFC 7523).
    applies_to_grants=["jwt_bearer"],
)
