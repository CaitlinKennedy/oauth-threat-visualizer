"""Access-token theft / replay runner (RFC 9449).

The honest client completes a full flow (the reusable victim-completes-redemption
path) and reads its resource; the attacker captures a copy of the issued access
token and replays it at the resource server.

One toggle decides the outcome:

- **DPoP off** — the token is a plain bearer token, so possession is authority.
  The attacker's replay succeeds and it reads the victim's resource.
- **DPoP on** — the honest client held a proof-of-possession key and the token is
  bound to it via ``cnf.jkt``. The same replay fails at the resource server's
  ``dpop_binding`` check: the attacker has the token but not the client's private
  key, so it cannot produce a proof whose thumbprint matches. The responsible
  capability is derived from that failing check, not hard-coded.
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
from . import Runner, register
from .support import (
    CHECK_TO_CAPABILITY,
    dpop_active,
    drive_honest_client,
    event_at,
    new_run_id,
)


def _matches(config: ScenarioConfig) -> bool:
    return "token_replay" in config.active_attacks()


def _run(config: ScenarioConfig) -> Trace:
    recorder = Recorder(new_run_id(), config)
    env = Environment()
    dpop = dpop_active(config)

    # Public client, no PKCE: the point here is token replay at the resource
    # server, not front-channel binding. DPoP is the lone property under test.
    client: Client = ClientImpl(
        recorder, env, registered_client=env.public_client, dpop=dpop
    )
    auth_server: AuthServer = AuthServerImpl(recorder, env)
    resource_server: ResourceServer = ResourceServerImpl(
        recorder, env.resource_server_config(), auth_server
    )
    attacker = AttackerImpl(recorder, env, active=True)

    # 1) The honest client completes the flow and reads its resource. When DPoP is
    #    on, the client presents proofs and the token it holds is sender-bound; the
    #    resource server's dpop_binding check PASSES for the honest holder.
    honest = drive_honest_client(
        client, auth_server=auth_server, resource_server=resource_server
    )
    honest_token = honest["token_response"].get("access_token")

    # 2) The attacker captures a copy of that token and replays it at the resource
    #    server. The real DPoP binding (or its absence) decides the outcome.
    attacker.capture_token(honest_token, obtained_from_seq=honest["result"]["seq"])
    outcome = attacker.replay_token(resource_server=resource_server)

    verdict = _verdict(
        recorder,
        dpop=dpop,
        attacker_read_resource=bool(outcome["got_resource"]),
        at_seq=outcome.get("at_seq"),
        user_got_token=bool(honest_token),
        user_accessed_resource=bool(honest["result"]["ok"]),
    )
    return recorder.seal(verdict)


def _verdict(
    recorder: Recorder,
    *,
    dpop: bool,
    attacker_read_resource: bool,
    at_seq: Optional[int],
    user_got_token: bool,
    user_accessed_resource: bool,
) -> Verdict:
    if attacker_read_resource:
        # DPoP off (or not holding): a stolen bearer token works anywhere.
        return Verdict(
            attacker_got_token=True,
            user_got_token=user_got_token,
            user_accessed_resource=user_accessed_resource,
            one_line=(
                "User obtained an access token: YES — the client completed the flow "
                "and read the resource. Attacker replayed the stolen token: YES — the "
                "token is a plain bearer token, so possession is all the resource "
                "server requires and the attacker reads the victim's resource "
                "(RFC 6750). Sender-constraining the token (DPoP) is what closes this."
            ),
            blocked_at_seq=None,
            responsible_capability=None,
            responsible_capabilities=[],
        )

    # DPoP on: the replay fails at the resource server. Attribute the block to the
    # capability that owns the failing check, read from the emitted trace.
    blocking = event_at(recorder, at_seq)
    check_name = blocking.check.name if (blocking and blocking.check) else "dpop_binding"
    responsible = CHECK_TO_CAPABILITY.get(check_name)
    return Verdict(
        attacker_got_token=False,
        user_got_token=user_got_token,
        user_accessed_resource=user_accessed_resource,
        one_line=(
            "User obtained an access token: YES — the client completed the flow with "
            "DPoP and read the resource. Attacker replayed the stolen token: NO — the "
            "token is sender-constrained (cnf.jkt), so the resource server requires a "
            "DPoP proof from the bound key. The attacker holds the token but not the "
            f"client's private key, so the {check_name} check fails and the resource "
            "server rejects the replay (RFC 9449 §7.1)."
        ),
        blocked_at_seq=at_seq,
        responsible_capability=responsible,
        responsible_capabilities=[responsible] if responsible else [],
    )


register(Runner(id="token_replay", matches=_matches, run=_run, order=90))
