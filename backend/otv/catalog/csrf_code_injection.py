"""CSRF / cross-session auth-code injection (RFC 6749 §10.12) — catalog entry.

The attacker obtains a valid authorization code for their *own* account on the
victim's client, then delivers it into the victim's browser so the victim's
client redeems it — binding the victim's client session to the attacker's account
(the classic login-CSRF variant). The ``state`` capability defeats it: the code
arrives without the ``state`` the victim's client generated, so an active ``state``
check rejects it before redemption.
"""

from __future__ import annotations

from ..contract import SpecRef
from ..registry import attack

attack(
    id="csrf_code_injection",
    label="CSRF (cross-session code injection)",
    description="Inject the attacker's own code into the victim's session (login CSRF).",
    spec_ref=SpecRef(rfc="RFC 6749", section="§10.12"),
    order=30,
    applies_to_grants=["authorization_code"],
)
