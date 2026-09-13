"""Auth-code injection runner (flows 2 & 3).

The victim starts a real flow and a real code is minted; the attacker captures it
and redeems it at the real token endpoint. PKCE — if active — is the only binding
the attacker cannot satisfy, so the outcome is decided by the protocol. The
verdict's responsible capability is *derived from the failing check in the emitted
trace*, never hard-coded.
"""

from __future__ import annotations

from typing import Optional

from ...actors.attacker import AttackerImpl
from ...actors.auth_server import AuthServer, AuthServerImpl
from ...actors.client import Client, ClientImpl
from ...actors.environment import Environment
from ...actors.resource_server import ResourceServer, ResourceServerImpl
from ...contract import ScenarioConfig, Trace, Verdict
from ...recorder import Recorder
from ...trace_context import acting
from . import Runner, register
from .support import CHECK_TO_CAPABILITY, event_at, new_run_id, pkce_method


def _matches(config: ScenarioConfig) -> bool:
    return "auth_code_injection" in config.active_attacks()


def _run(config: ScenarioConfig) -> Trace:
    recorder = Recorder(new_run_id(), config)
    env = Environment()
    method = pkce_method(config)

    # The victim uses the PUBLIC client (native/SPA, no secret). With no client
    # secret in play, PKCE is honestly the only binding that can stop the attacker.
    client: Client = ClientImpl(
        recorder, env, pkce_method=method, registered_client=env.public_client
    )
    auth_server: AuthServer = AuthServerImpl(recorder, env)
    resource_server: ResourceServer = ResourceServerImpl(
        recorder, env.resource_server_config(), auth_server
    )
    attacker = AttackerImpl(recorder, env, active=True)
    assert attacker.is_active()

    # 1) The victim begins a genuine flow and the AS mints a real code. (The
    #    victim's client never gets to redeem it — the attacker races/captures it.)
    with acting(on_behalf_of="user"):
        started = client.start_authorization()
        redirect = auth_server.authorize(started["params"])

    # 2) The attacker captures the code and attempts to redeem it as itself.
    with acting(on_behalf_of="attacker"):
        attacker.intercept_code(redirect["code"], obtained_from_seq=redirect["issue_seq"])
        outcome = attacker.redeem_code(auth_server=auth_server)
        if outcome["got_token"]:
            # Demonstrate impact: the stolen-flow token reads the victim's profile.
            attacker.access_resource(resource_server=resource_server)

    attacker_got_token = bool(outcome["got_token"])
    verdict = _verdict(recorder, attacker_got_token, outcome.get("at_seq"))
    return recorder.seal(verdict)


def _verdict(recorder: Recorder, attacker_got_token: bool, at_seq: Optional[int]) -> Verdict:
    """Build the injection verdict, attributing a block to the failing check.

    The responsible capability is looked up from the actual failing ``check`` at
    ``at_seq`` in the emitted trace — the block is what the protocol produced, and
    the label is derived from it rather than assumed.
    """
    if attacker_got_token:
        return Verdict(
            attacker_got_token=True,
            user_got_token=False,
            user_accessed_resource=False,
            one_line=(
                "Attacker obtained an access token: YES — auth-code injection "
                "succeeded. With no PKCE, a captured authorization code is enough to "
                "redeem a token for the victim. User obtained an access token: NO — "
                "the victim's code was intercepted before its client could use it."
            ),
            blocked_at_seq=None,
            responsible_capability=None,
            responsible_capabilities=[],
        )

    blocking_event = event_at(recorder, at_seq)
    responsible: Optional[str] = None
    if blocking_event is not None and blocking_event.check is not None:
        responsible = CHECK_TO_CAPABILITY.get(blocking_event.check.name)
    responsible_caps = [responsible] if responsible else []
    cap_phrase = f" — {responsible} verifier mismatch" if responsible == "pkce" else ""
    return Verdict(
        attacker_got_token=False,
        user_got_token=False,
        user_accessed_resource=False,
        one_line=(
            "Attacker obtained an access token: NO" + cap_phrase + ". The identical "
            "auth-code injection fails: the attacker holds the code but cannot present "
            "the matching code_verifier, so the token endpoint rejects the exchange. "
            "User obtained an access token: NO — the victim's code was intercepted."
        ),
        blocked_at_seq=at_seq,
        responsible_capability=responsible,
        responsible_capabilities=responsible_caps,
    )


register(Runner(id="auth_code_injection", matches=_matches, run=_run))
