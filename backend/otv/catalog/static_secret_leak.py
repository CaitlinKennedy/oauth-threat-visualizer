"""Static-secret leak attack (RFC 6749 §10.3) — self-registering catalog entry.

The attack runs against the client-credentials grant: a confidential client's
*static* ``client_secret`` leaks (a config dump, a log, a committed file) and the
attacker replays it to authenticate as the client and mint its own tokens — full,
permanent impersonation, because the secret never rotates and possessing it *is*
the authority.

The counter-lesson is the ``client_auth`` capability's ``private_key_jwt`` method
(RFC 7523 §2.2): the secret never transits, so what an attacker can capture is at
most a spent ``client_assertion`` — short-lived and ``jti``-bound, so replaying it
fails and a new one cannot be forged without the client's private key. The
paired-diff preset runs the identical leak under both to show the divergence.
"""

from __future__ import annotations

from ..contract import SpecRef
from ..registry import attack

attack(
    id="static_secret_leak",
    label="Static-secret leak",
    description=(
        "A never-rotating client secret is captured and replayed to impersonate "
        "the client at the token endpoint."
    ),
    spec_ref=SpecRef(rfc="RFC 6749", section="§10.3"),
    order=50,
    applies_to_grants=["client_credentials"],
)
