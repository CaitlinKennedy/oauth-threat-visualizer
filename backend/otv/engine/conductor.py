"""The conductor: runs a scenario end-to-end and produces a validated Trace.

It wires a :class:`ScenarioConfig` through the four actors — depending only on
their service-API *interfaces* — drives the real OAuth exchange, computes the
verdict, and validates the trace against the frozen contract before returning
it. The UI is a pure function of what this returns.

Because callers here bind to the interfaces (:class:`Client`, :class:`AuthServer`,
:class:`ResourceServer`, :class:`Attacker`) and not the concrete impls,
promoting any actor to a standalone REST service later is an impl/transport swap
with no change to this orchestration, the contract, or the UI.

Phase 0 supports one path: the authorization-code grant with no active attack.
Anything else raises :class:`UnsupportedScenario`, which the API turns into the
committed fixture fallback.
"""

from __future__ import annotations

from .. import crypto
from ..contract import ScenarioConfig, Trace, Verdict, validate
from ..recorder import Recorder
from ..actors.attacker import Attacker, AttackerImpl
from ..actors.auth_server import AuthServer, AuthServerImpl
from ..actors.client import Client, ClientImpl
from ..actors.environment import Environment
from ..actors.resource_server import ResourceServer, ResourceServerImpl


class UnsupportedScenario(Exception):
    """Raised when a scenario config is outside what this phase implements."""


def run(config: ScenarioConfig) -> Trace:
    """Execute ``config`` and return a validated :class:`Trace`."""
    if config.grant != "authorization_code":
        raise UnsupportedScenario(f"grant {config.grant!r} is not implemented yet")
    if config.active_attacks():
        raise UnsupportedScenario("attacks are not implemented until Phase 1")

    trace = _run_happy_path(config)
    validate(trace)  # guard: never hand the UI a trace that breaks the contract
    return trace


def _run_happy_path(config: ScenarioConfig) -> Trace:
    correlation_id = crypto.new_opaque_token(prefix="run_")
    recorder = Recorder(correlation_id, config)
    env = Environment()

    # Construct the concrete impls, but bind callers to the interfaces.
    client: Client = ClientImpl(recorder, env)
    auth_server: AuthServer = AuthServerImpl(recorder, env)
    resource_server: ResourceServer = ResourceServerImpl(recorder, env, auth_server)
    attacker: Attacker = AttackerImpl(recorder, env)
    assert not attacker.is_active()  # present but idle this phase

    # 1) Client begins the authorization-code flow.
    started = client.start_authorization(on_behalf_of="user")

    # 2) Authorization server authenticates the user and redirects with a code.
    redirect = auth_server.authorize(
        started["params"], on_behalf_of="user", refs=[started["seq"]]
    )

    # 3) Client receives the redirect and validates state.
    received = client.receive_redirect(
        redirect, request_seq=started["seq"], on_behalf_of="user"
    )

    # 4) Client exchanges the code for a token over the back channel (via the AS
    #    interface).
    exchanged = client.exchange_code(
        received["code"],
        redirect_seq=received["seq"],
        auth_server=auth_server,
        on_behalf_of="user",
    )
    token_response = exchanged["token_response"]

    # 5) Client calls the resource server with the access token (via the RS
    #    interface).
    result = client.access_resource(
        token_seq=exchanged["seq"],
        resource_server=resource_server,
        on_behalf_of="user",
    )

    user_got_token = bool(token_response.get("access_token"))
    user_accessed_resource = bool(result["ok"])
    verdict = Verdict(
        attacker_got_token=False,
        user_got_token=user_got_token,
        user_accessed_resource=user_accessed_resource,
        one_line=(
            "User obtained an access token: YES — the client completed the "
            "authorization-code flow and the resource server honored the token. "
            "Attacker obtained an access token: NO — no attack was attempted."
        ),
        blocked_at_seq=None,
        responsible_capability=None,
    )
    return recorder.seal(verdict)
