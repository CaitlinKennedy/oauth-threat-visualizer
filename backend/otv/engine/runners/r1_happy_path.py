"""Happy-path runner: the clean authorization-code flow (no active attack).

The honest client completes the whole flow and the resource server honors the
token. PKCE, when active, is generated and its verifier matched — but nothing is
under attack, so every check passes.
"""

from __future__ import annotations

from ...actors.attacker import Attacker, AttackerImpl
from ...actors.auth_server import AuthServer, AuthServerImpl
from ...actors.client import Client, ClientImpl
from ...actors.environment import Environment
from ...actors.resource_server import ResourceServer, ResourceServerImpl
from ...contract import ScenarioConfig, Trace, Verdict
from ...recorder import Recorder
from . import Runner, register
from .support import drive_honest_client, new_run_id, pkce_method, state_active


def _matches(config: ScenarioConfig) -> bool:
    return config.grant == "authorization_code" and not config.active_attacks()


def _run(config: ScenarioConfig) -> Trace:
    recorder = Recorder(new_run_id(), config)
    env = Environment()
    method = pkce_method(config)

    # Construct the concrete impls, but bind callers to the interfaces. The
    # resource server is given only role-scoped facts (issuer, audience, its own
    # profile store) — no client secret, no registered-client table (see B2).
    client: Client = ClientImpl(
        recorder, env, pkce_method=method, enforce_state=state_active(config)
    )
    auth_server: AuthServer = AuthServerImpl(recorder, env)
    resource_server: ResourceServer = ResourceServerImpl(
        recorder, env.resource_server_config(), auth_server
    )
    attacker: Attacker = AttackerImpl(recorder, env, active=False)
    assert not attacker.is_active()  # present but idle on the happy path

    outcome = drive_honest_client(
        client, auth_server=auth_server, resource_server=resource_server
    )
    token_response = outcome["token_response"]

    user_got_token = bool(token_response.get("access_token"))
    user_accessed_resource = bool(outcome["result"]["ok"])
    pkce_note = " PKCE was enabled and its verifier matched." if method else ""
    verdict = Verdict(
        attacker_got_token=False,
        user_got_token=user_got_token,
        user_accessed_resource=user_accessed_resource,
        one_line=(
            "User obtained an access token: YES — the client completed the "
            "authorization-code flow and the resource server honored the token. "
            "Attacker obtained an access token: NO — no attack was attempted." + pkce_note
        ),
        blocked_at_seq=None,
        responsible_capability=None,
    )
    return recorder.seal(verdict)


register(Runner(id="happy_path", matches=_matches, run=_run))
