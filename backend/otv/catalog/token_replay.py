"""Access-token theft / replay attack (RFC 9449 §1) — self-registering entry.

The honest client obtains a real access token and reads its resource; the
attacker captures a copy of that token and replays it at the resource server.
With a plain bearer token the replay succeeds — possession is the only
requirement. With a DPoP sender-constrained token the same replay fails: the
attacker holds the token bytes but not the client's proof-of-possession key, so
the resource server's key-binding check rejects it.
"""

from __future__ import annotations

from ..contract import SpecRef
from ..registry import attack

attack(
    id="token_replay",
    label="Access-token replay (resource server)",
    description="Reuse a stolen access token at the resource server.",
    spec_ref=SpecRef(rfc="RFC 9449", section="§1"),
    order=60,
    # Every grant issues an access token, so every grant can have one stolen.
    applies_to_grants=[],
)
