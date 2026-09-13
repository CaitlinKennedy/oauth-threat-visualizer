"""Shared helpers for scenario runners.

Small utilities several runners need — resolving the active PKCE method, mapping a
failing ``check`` to the capability that owns it, looking up a step by ``seq``,
and driving the honest client through a full authorization-code flow. Keeping
these here (rather than in any one runner) is what lets a later phase's runner
reuse them without importing another runner.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ... import crypto
from ...contract import ScenarioConfig, StepEvent
from ...recorder import Recorder
from ...trace_context import acting
from ...actors.auth_server import AuthServer
from ...actors.client import Client
from ...actors.resource_server import ResourceServer

# Which capability a given first-class check enforces. Used to attribute a block
# to the responsible capability *from the emitted trace* (the failing check),
# rather than hard-coding the verdict.
CHECK_TO_CAPABILITY = {
    "pkce_verifier_match": "pkce",
    "state_matches_session": "state",
}


def pkce_method(config: ScenarioConfig) -> Optional[str]:
    """The active PKCE method for this run, or ``None`` when PKCE is off."""
    st = config.capabilities.get("pkce")
    if st is None or not st.active:
        return None
    method = st.params.get("method", "S256")
    return method if method in crypto.PKCE_METHODS else "S256"


def state_active(config: ScenarioConfig) -> bool:
    """Whether the ``state`` capability is active (enforced) for this run."""
    st = config.capabilities.get("state")
    return bool(st and st.active)


def event_at(recorder: Recorder, seq: Optional[int]) -> Optional[StepEvent]:
    """The recorded event with this ``seq`` (or ``None``)."""
    if seq is None:
        return None
    for e in recorder.events:
        if e.seq == seq:
            return e
    return None


def new_run_id() -> str:
    return crypto.new_opaque_token(prefix="run_")


def drive_honest_client(
    client: Client,
    *,
    auth_server: AuthServer,
    resource_server: ResourceServer,
) -> Dict[str, Any]:
    """Drive the honest user through a full authorization-code flow.

    This is the *victim-completes-redemption* path: the client starts the flow,
    the AS mints a code, the client receives the redirect, exchanges the code for
    a real token, and calls the protected resource — all on behalf of the user.
    Returns the code, token response, and resource result so a runner can build a
    verdict or stage a follow-on attack (e.g. replaying the now-spent code).
    """
    with acting(on_behalf_of="user"):
        started = client.start_authorization()
        redirect = auth_server.authorize(started["params"])
        received = client.receive_redirect(redirect)
        exchanged = client.exchange_code(received["code"], auth_server=auth_server)
        result = client.access_resource(resource_server=resource_server)
    return {
        "code": received["code"],
        "issue_seq": redirect.get("issue_seq"),
        "token_response": exchanged["token_response"],
        "result": result,
    }
