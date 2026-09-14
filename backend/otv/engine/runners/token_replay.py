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

from ...actors.attacker import AttackerImpl
from ...actors.auth_server import AuthServer, AuthServerImpl
from ...actors.client import Client, ClientImpl
from ...actors.environment import Environment
from ...actors.resource_server import ResourceServer, ResourceServerImpl
from ...contract import ScenarioConfig, Trace
from ...recorder import Recorder
from . import Runner, register
from .support import (
    dpop_active,
    drive_honest_client,
    new_run_id,
    token_replay_verdict,
)


def _matches(config: ScenarioConfig) -> bool:
    return config.grant == "authorization_code" and "token_replay" in config.active_attacks()


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

    verdict = token_replay_verdict(
        recorder,
        attacker_read_resource=bool(outcome["got_resource"]),
        at_seq=outcome.get("at_seq"),
        user_got_token=bool(honest_token),
        user_accessed_resource=bool(honest["result"]["ok"]),
        honest_bearer=(
            "User obtained an access token: YES — the client completed the flow "
            "and read the resource."
        ),
        honest_dpop=(
            "User obtained an access token: YES — the client completed the flow with "
            "DPoP and read the resource."
        ),
    )
    return recorder.seal(verdict)



register(Runner(id="token_replay", matches=_matches, run=_run, order=90))
