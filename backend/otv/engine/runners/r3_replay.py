"""Auth-code replay runner (RFC 6749 §4.1.2).

The honest client completes a full redemption (the victim-completes-redemption
path, reused from :func:`support.drive_honest_client`), then the attacker replays
the very same code. The second redemption fails at the genuine single-use check
in the code store: a captured authorization code is worthless once spent.

``state`` is not the point here and PKCE is off, so single use is honestly the
lone property under test — a public client is used so client authentication is
not a separate gate.
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
from .support import drive_honest_client, event_at, new_run_id


def _matches(config: ScenarioConfig) -> bool:
    return "code_token_replay" in config.active_attacks()


def _run(config: ScenarioConfig) -> Trace:
    recorder = Recorder(new_run_id(), config)
    env = Environment()

    # Public client, no PKCE: single use is the lone property that decides the
    # replay (no client secret and no verifier stand in the way).
    client: Client = ClientImpl(recorder, env, registered_client=env.public_client)
    auth_server: AuthServer = AuthServerImpl(recorder, env)
    resource_server: ResourceServer = ResourceServerImpl(
        recorder, env.resource_server_config(), auth_server
    )
    attacker = AttackerImpl(recorder, env, active=True)

    # 1) The honest client completes a full redemption — the reusable
    #    victim-completes-redemption path — spending the single-use code.
    honest = drive_honest_client(
        client, auth_server=auth_server, resource_server=resource_server
    )

    # 2) The attacker, holding a copy captured from the front channel, replays the
    #    now-spent code. The single-use check rejects the second redemption.
    with acting(on_behalf_of="attacker"):
        attacker.capture_code(honest["code"], obtained_from_seq=honest["issue_seq"])
        outcome = attacker.replay_code(auth_server=auth_server)

    user_got_token = bool(honest["token_response"].get("access_token"))
    user_accessed_resource = bool(honest["result"]["ok"])
    verdict = _verdict(
        recorder,
        attacker_got_token=bool(outcome["got_token"]),
        at_seq=outcome.get("at_seq"),
        user_got_token=user_got_token,
        user_accessed_resource=user_accessed_resource,
    )
    return recorder.seal(verdict)


def _verdict(
    recorder: Recorder,
    *,
    attacker_got_token: bool,
    at_seq: Optional[int],
    user_got_token: bool,
    user_accessed_resource: bool,
) -> Verdict:
    if attacker_got_token:
        # Defensive only — a spent single-use code must not redeem twice.
        return Verdict(
            attacker_got_token=True,
            user_got_token=user_got_token,
            user_accessed_resource=user_accessed_resource,
            one_line=(
                "Attacker obtained an access token: YES — the replayed code was "
                "accepted, so single-use enforcement is not holding."
            ),
            blocked_at_seq=None,
            responsible_capability=None,
        )

    # The block is the single-use check the code store just failed — an intrinsic
    # property of the authorization code, not a toggleable capability, so no
    # responsible_capability is named (the blocking check is authoritative).
    blocking = event_at(recorder, at_seq)
    check_name = blocking.check.name if (blocking and blocking.check) else "single use"
    return Verdict(
        attacker_got_token=False,
        user_got_token=user_got_token,
        user_accessed_resource=user_accessed_resource,
        one_line=(
            "User obtained an access token: YES — the honest client completed the "
            "flow and read the resource. Attacker obtained an access token: NO — the "
            "authorization code is single-use, so replaying the already-redeemed code "
            f"fails the {check_name} check and the token endpoint rejects it "
            "(RFC 6749 §4.1.2)."
        ),
        blocked_at_seq=at_seq,
        responsible_capability=None,
        responsible_capabilities=[],
    )


register(Runner(id="code_token_replay", matches=_matches, run=_run))
