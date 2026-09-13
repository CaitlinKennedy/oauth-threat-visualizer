"""The conductor: runs a scenario end-to-end and produces a validated Trace.

It wires a :class:`ScenarioConfig` through the four actors — depending only on
their service-API *interfaces* — drives the real OAuth exchange, computes the
verdict, and validates the trace against the frozen contract before returning
it. The UI is a pure function of what this returns.

Because callers here bind to the interfaces (:class:`Client`, :class:`AuthServer`,
:class:`ResourceServer`, :class:`Attacker`) and not the concrete impls,
promoting any actor to a standalone REST service later is an impl/transport swap
with no change to this orchestration, the contract, or the UI.

Phase 1 supports the authorization-code grant in two shapes:

- **happy path** — no active attack (optionally with PKCE), the honest flow; and
- **auth-code injection** — the attacker obtains the victim's code and tries to
  redeem it. With PKCE off the attacker wins; with PKCE on the identical attack
  fails at the real ``pkce_verifier_match`` check. The block is produced by the
  protocol, and the verdict's responsible capability is *derived from the failing
  check in the emitted trace*, never hard-coded.

Anything outside this phase raises :class:`UnsupportedScenario`, which the API
turns into an explicit "not available" response (never a fake success).
"""

from __future__ import annotations

from typing import Optional

from .. import crypto, registry
from ..contract import ScenarioConfig, StepEvent, Trace, Verdict, validate
from ..recorder import Recorder
from ..trace_context import acting
from ..actors.attacker import Attacker, AttackerImpl
from ..actors.auth_server import AuthServer, AuthServerImpl
from ..actors.client import Client, ClientImpl
from ..actors.environment import Environment
from ..actors.resource_server import ResourceServer, ResourceServerImpl

# Which capability a given first-class check enforces. Used to attribute a block
# to the responsible capability *from the emitted trace* (the failing check),
# rather than hard-coding the verdict.
_CHECK_TO_CAPABILITY = {
    "pkce_verifier_match": "pkce",
}


class UnsupportedScenario(Exception):
    """Raised when a scenario config is outside what this phase implements."""


def run(config: ScenarioConfig) -> Trace:
    """Execute ``config`` and return a validated :class:`Trace`."""
    if config.grant != "authorization_code":
        raise UnsupportedScenario(f"grant {config.grant!r} is not implemented yet")
    _reject_unavailable_features(config)

    if "auth_code_injection" in config.active_attacks():
        trace = _run_injection(config)
    elif config.active_attacks():
        # No other attack is runnable this phase (the guard above would have caught
        # an unavailable one; this catches an available attack we don't route yet).
        raise UnsupportedScenario(
            f"attack {config.active_attacks()!r} is not routed in this phase"
        )
    else:
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


def _pkce_method(config: ScenarioConfig) -> Optional[str]:
    """The active PKCE method for this run, or ``None`` when PKCE is off."""
    st = config.capabilities.get("pkce")
    if st is None or not st.active:
        return None
    method = st.params.get("method", "S256")
    return method if method in crypto.PKCE_METHODS else "S256"


def _run_happy_path(config: ScenarioConfig) -> Trace:
    correlation_id = crypto.new_opaque_token(prefix="run_")
    recorder = Recorder(correlation_id, config)
    env = Environment()
    pkce_method = _pkce_method(config)

    # Construct the concrete impls, but bind callers to the interfaces. The
    # resource server is given only role-scoped facts (issuer, audience, its own
    # profile store) — no client secret, no registered-client table (see B2).
    client: Client = ClientImpl(recorder, env, pkce_method=pkce_method)
    auth_server: AuthServer = AuthServerImpl(recorder, env)
    resource_server: ResourceServer = ResourceServerImpl(
        recorder, env.resource_server_config(), auth_server
    )
    attacker: Attacker = AttackerImpl(recorder, env, active=False)
    assert not attacker.is_active()  # present but idle on the happy path

    # Every step in the happy path serves the honest user. Correlation metadata is
    # supplied by the ambient trace context, not threaded across the interfaces.
    with acting(on_behalf_of="user"):
        started = client.start_authorization()
        redirect = auth_server.authorize(started["params"])
        received = client.receive_redirect(redirect)
        exchanged = client.exchange_code(received["code"], auth_server=auth_server)
        token_response = exchanged["token_response"]
        result = client.access_resource(resource_server=resource_server)

    user_got_token = bool(token_response.get("access_token"))
    user_accessed_resource = bool(result["ok"])
    pkce_note = " PKCE was enabled and its verifier matched." if pkce_method else ""
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


def _run_injection(config: ScenarioConfig) -> Trace:
    """Auth-code injection against the live endpoints (flow 2 / flow 3).

    The victim starts a real flow and a real code is minted; the attacker captures
    it and redeems it at the real token endpoint. PKCE — if active — is the only
    binding the attacker cannot satisfy, so the outcome is decided by the protocol.
    """
    correlation_id = crypto.new_opaque_token(prefix="run_")
    recorder = Recorder(correlation_id, config)
    env = Environment()
    pkce_method = _pkce_method(config)

    client: Client = ClientImpl(recorder, env, pkce_method=pkce_method)
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
    verdict = _injection_verdict(recorder, attacker_got_token, outcome.get("at_seq"))
    return recorder.seal(verdict)


def _injection_verdict(
    recorder: Recorder, attacker_got_token: bool, at_seq: Optional[int]
) -> Verdict:
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

    blocking_event = _event_at(recorder, at_seq)
    responsible: Optional[str] = None
    if blocking_event is not None and blocking_event.check is not None:
        responsible = _CHECK_TO_CAPABILITY.get(blocking_event.check.name)
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


def _event_at(recorder: Recorder, seq: Optional[int]) -> Optional[StepEvent]:
    if seq is None:
        return None
    for e in recorder.events:
        if e.seq == seq:
            return e
    return None
