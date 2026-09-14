"""Shared helpers for scenario runners.

Small utilities several runners need — resolving the active PKCE method, mapping a
failing ``check`` to the capability that owns it, looking up a step by ``seq``,
and driving the honest client through a full authorization-code flow. Keeping
these here (rather than in any one runner) is what lets any runner reuse them
without importing another runner.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ... import crypto
from ...contract import ScenarioConfig, StepEvent, Verdict
from ...recorder import Recorder
from ...registry import ATTACKS, CAPABILITIES
from ...trace_context import acting
from ...actors.auth_server import AuthServer
from ...actors.client import Client
from ...actors.resource_server import ResourceServer


def _build_check_to_capability() -> Dict[str, str]:
    """Invert every catalogued item's ``check_names`` into check -> owning id.

    This is what lets a runner attribute a block to the responsible capability
    *from the emitted trace* (the failing check) without a hard-coded verdict.
    Built by scanning the registry (each capability/attack declares its own
    ``check_names`` in its own catalog file — see ``otv.registry.RegistryItem``),
    so a future capability needs no edit here: it just declares its check names
    where it is defined.
    """
    mapping: Dict[str, str] = {}
    for item in (*CAPABILITIES, *ATTACKS):
        for name in item.check_names:
            owner = mapping.get(name)
            if owner is not None and owner != item.id:
                raise ValueError(
                    f"check {name!r} is claimed by both {owner!r} and {item.id!r}"
                )
            mapping[name] = item.id
    return mapping


# Which capability a given first-class check enforces, derived from the registry
# (each capability declares its own ``check_names``) rather than hand-maintained
# here. Used to attribute a block to the responsible capability *from the
# emitted trace* (the failing check), rather than hard-coding the verdict.
CHECK_TO_CAPABILITY: Dict[str, str] = _build_check_to_capability()


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


def dpop_active(config: ScenarioConfig) -> bool:
    """Whether the ``dpop`` capability is active (sender-constraining) for this run."""
    st = config.capabilities.get("dpop")
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


def token_replay_verdict(
    recorder: Recorder,
    *,
    attacker_read_resource: bool,
    at_seq: Optional[int],
    user_got_token: bool,
    user_accessed_resource: bool,
    honest_bearer: str,
    honest_dpop: str,
    resource_owner: str = "the victim's",
) -> Verdict:
    """The verdict for an access-token replay at the resource server.

    Shared by every grant's token-replay runner: only how the honest party got its
    token differs (``honest_bearer`` / ``honest_dpop`` describe that), while the
    replay and its DPoP binding are identical. A block is attributed to the
    capability owning the failing check in the emitted trace.
    """
    if attacker_read_resource:
        # DPoP off (or not holding): a stolen bearer token works anywhere.
        return Verdict(
            attacker_got_token=True,
            user_got_token=user_got_token,
            user_accessed_resource=user_accessed_resource,
            one_line=(
                f"{honest_bearer} Attacker replayed the stolen token: YES — the "
                "token is a plain bearer token, so possession is all the resource "
                f"server requires and the attacker reads {resource_owner} resource "
                "(RFC 6750). Sender-constraining the token (DPoP) is what closes this."
            ),
            blocked_at_seq=None,
            responsible_capability=None,
            responsible_capabilities=[],
        )

    blocking = event_at(recorder, at_seq)
    check_name = blocking.check.name if (blocking and blocking.check) else "dpop_binding"
    responsible = CHECK_TO_CAPABILITY.get(check_name)
    return Verdict(
        attacker_got_token=False,
        user_got_token=user_got_token,
        user_accessed_resource=user_accessed_resource,
        one_line=(
            f"{honest_dpop} Attacker replayed the stolen token: NO — the "
            "token is sender-constrained (cnf.jkt), so the resource server requires a "
            "DPoP proof from the bound key. The attacker holds the token but not the "
            f"client's private key, so the {check_name} check fails and the resource "
            "server rejects the replay (RFC 9449 §7.1)."
        ),
        blocked_at_seq=at_seq,
        responsible_capability=responsible,
        responsible_capabilities=[responsible] if responsible else [],
    )


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
