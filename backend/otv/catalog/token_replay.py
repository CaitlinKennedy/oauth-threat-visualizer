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
    label="Access-token theft / replay",
    description="Reuse a stolen access token at the resource server.",
    spec_ref=SpecRef(rfc="RFC 9449", section="§1"),
    order=60,
    # The replay is staged on a token issued by the authorization-code flow; the
    # other grants carry their own replay attacks (assertion replay, static
    # secret leak).
    applies_to_grants=["authorization_code"],
)
