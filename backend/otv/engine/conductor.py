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

from .. import crypto, registry
from ..contract import ScenarioConfig, Trace, Verdict, validate
from ..recorder import Recorder
from ..trace_context import acting
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
    _reject_unavailable_features(config)

    trace = _run_happy_path(config)
    validate(trace)  # guard: never hand the UI a trace that breaks the contract
    return trace


def _reject_unavailable_features(config: ScenarioConfig) -> None:
    """Reject any active capability/attack that this build does not implement.

    Prevents config and trace from disagreeing: if a caller turns on a feature the
    registry marks not-yet-available, we refuse the run rather than silently
    ignore the toggle and emit a trace that contradicts the requested config.
    """
    for kind, active in (
        ("capability", config.active_capabilities()),
        ("attack", config.active_attacks()),
    ):
        for fid in active:
            item = registry.get(fid)
            if item is None:
                raise UnsupportedScenario(f"unknown {kind} {fid!r}")
            if not item.available:
                raise UnsupportedScenario(
                    f"{kind} {fid!r} is not implemented until phase {item.phase}"
                )


def _run_happy_path(config: ScenarioConfig) -> Trace:
    correlation_id = crypto.new_opaque_token(prefix="run_")
    recorder = Recorder(correlation_id, config)
    env = Environment()

    # Construct the concrete impls, but bind callers to the interfaces. The
    # resource server is given only role-scoped facts (issuer, audience, its own
    # profile store) — no client secret, no registered-client table (see B2).
    client: Client = ClientImpl(recorder, env)
    auth_server: AuthServer = AuthServerImpl(recorder, env)
    resource_server: ResourceServer = ResourceServerImpl(
        recorder, env.resource_server_config(), auth_server
    )
    attacker: Attacker = AttackerImpl(recorder, env)
    assert not attacker.is_active()  # present but idle this phase

    # Every step in the happy path serves the honest user. Correlation metadata is
    # supplied by the ambient trace context, not threaded across the interfaces.
    with acting(on_behalf_of="user"):
        # 1) Client begins the authorization-code flow.
        started = client.start_authorization()

        # 2) Authorization server authenticates the user and redirects with a code.
        redirect = auth_server.authorize(started["params"])

        # 3) Client receives the redirect and validates state.
        received = client.receive_redirect(redirect)

        # 4) Client exchanges the code for a token over the back channel (via the
        #    AS interface).
        exchanged = client.exchange_code(received["code"], auth_server=auth_server)
        token_response = exchanged["token_response"]

        # 5) Client calls the resource server with the access token (via the RS
        #    interface).
        result = client.access_resource(resource_server=resource_server)

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
