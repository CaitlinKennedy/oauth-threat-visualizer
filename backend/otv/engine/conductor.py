"""The conductor: runs a scenario end-to-end and produces a validated Trace.

It resolves a :class:`ScenarioConfig` to a **registered runner** (see
:mod:`otv.engine.runners`), drives it through the four actors — depending only on
their service-API *interfaces* — and validates the resulting trace against the
frozen contract before returning it. The UI is a pure function of what this
returns.

Because runners bind to the interfaces (:class:`~otv.actors.client.Client`,
:class:`~otv.actors.auth_server.AuthServer`,
:class:`~otv.actors.resource_server.ResourceServer`,
:class:`~otv.actors.attacker.Attacker`) and not the concrete impls, promoting any
actor to a standalone REST service later is an impl/transport swap with no change
to this orchestration, the contract, or the UI.

**Extension point.** The conductor no longer knows the individual scenarios: it
dispatches to whichever runner matches the config. A later phase adds a scenario
by dropping a self-registering module in :mod:`otv.engine.runners` — never by
editing a branch here. Anything no runner matches raises
:class:`UnsupportedScenario`, which the API turns into an explicit "not available"
response (never a fake success).
"""

from __future__ import annotations

from . import runners
from .. import registry
from ..contract import ScenarioConfig, Trace, validate


class UnsupportedScenario(Exception):
    """Raised when a scenario config is outside what this build implements."""


def run(config: ScenarioConfig) -> Trace:
    """Execute ``config`` via its matching runner and return a validated Trace."""
    _reject_unavailable_features(config)
    runner = runners.select(config)
    if runner is None:
        raise UnsupportedScenario(_why_unsupported(config))
    trace = runner.run(config)
    validate(trace)  # guard: never hand the UI a trace that breaks the contract
    return trace


def _why_unsupported(config: ScenarioConfig) -> str:
    if config.grant != "authorization_code":
        return f"grant {config.grant!r} is not implemented yet"
    if config.active_attacks():
        return f"attack {config.active_attacks()!r} is not routed in this build"
    return "no runner matches this scenario config"


def _reject_unavailable_features(config: ScenarioConfig) -> None:
    """Reject any active capability/attack that this build does not implement.

    Prevents config and trace from disagreeing: if a caller turns on a feature the
    registry marks not-yet-available, we refuse the run rather than silently
    ignore the toggle and emit a trace that contradicts the requested config.
    Also rejects a feature that doesn't apply to the requested grant at all
    (e.g. an authorization-code-only attack under ``client_credentials``) — the
    picker hides these, but a hand-built config could still request one, which
    would otherwise fall through to whichever runner matches on other grounds
    and hand back a trace that disagrees with the request.
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
            if item.applies_to_grants and config.grant not in item.applies_to_grants:
                raise UnsupportedScenario(
                    f"{kind} {fid!r} does not apply to grant {config.grant!r}"
                )
