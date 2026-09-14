"""Seam-locking tests for the self-registering catalog/runner plugin points.

``otv/registry.py`` and ``otv/engine/runners/__init__.py`` both promise the same
shape of extension: a new file dropped into ``otv/catalog`` or
``otv/engine/runners`` self-registers, with an explicit ``order`` controlling
display/match order and duplicate ids refused rather than silently clobbering
each other. Those promises are otherwise only exercised implicitly by whichever
capabilities happen to exist; this module pins them directly so a later mistake
(a wrong ``order``, a copy-pasted id, a runner whose predicate overlaps
another's) fails here — fast and specifically — instead of showing up as
unexplained fixture drift or a picker that renders in the wrong order.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from otv import registry, scenarios
from otv.contract import SpecRef, trace_from_dict
from otv.engine import runners as runners_pkg
from scripts.regen import COMPARE_FIXTURES, TRACE_FIXTURES

BACKEND = Path(__file__).resolve().parent.parent
BACKEND_FIXTURES = BACKEND / "otv" / "fixtures"


# --- Deterministic registration order ---------------------------------------
# The catalog and runner packages both expose their items sorted by an explicit
# ``order`` (ties broken by id), independent of filename. Pin the *order* (not
# just membership) so a wrong ``order`` on a new item — which would reorder the
# picker or change runner precedence — is caught immediately.


def test_capability_registration_order_is_stable():
    assert [c.id for c in registry.CAPABILITIES] == [
        "pkce",
        "state",
        "assertion_replay_protection",
        "client_auth",
        "dpop",
    ]


def test_attack_registration_order_is_stable():
    assert [a.id for a in registry.ATTACKS] == [
        "auth_code_injection",
        "code_token_replay",
        "csrf_code_injection",
        "assertion_replay",
        "static_secret_leak",
        "token_replay",
    ]


def test_runner_registration_order_is_stable():
    assert [r.id for r in runners_pkg.all_runners()] == [
        "happy_path",
        "auth_code_injection",
        "code_token_replay",
        "csrf_code_injection",
        "jwt_bearer_happy",
        "assertion_replay",
        "client_credentials",
        "static_secret_leak",
        "token_replay",
    ]


# --- runners.select() precedence / mutual exclusivity -----------------------
# Matchers are supposed to be mutually exclusive (each keys off a distinct
# active attack, and the happy-path runner keys off *no* active attack).
# Exercise that against every config the app actually ships, not just the ones
# a runner's own module happens to test.


def _shipped_preset_configs():
    """(label, ScenarioConfig) for every config named in PRESETS, incl. compare sides."""
    configs = []
    for preset in scenarios.PRESETS:
        configs.append((preset["id"], scenarios.config_from_dict(preset["config"])))
        if "compare" in preset:
            configs.append(
                (
                    f"{preset['id']}:baseline",
                    scenarios.config_from_dict(preset["compare"]["baseline"]),
                )
            )
            configs.append(
                (
                    f"{preset['id']}:variant",
                    scenarios.config_from_dict(preset["compare"]["variant"]),
                )
            )
    return configs


_PRESET_CONFIGS = _shipped_preset_configs()


@pytest.mark.parametrize(
    "label,config", _PRESET_CONFIGS, ids=[c[0] for c in _PRESET_CONFIGS]
)
def test_exactly_one_runner_matches_each_shipped_preset(label, config):
    matches = [r for r in runners_pkg.all_runners() if r.matches(config)]
    assert len(matches) == 1, (
        f"{label}: expected exactly one runner to match, got "
        f"{[r.id for r in matches]}"
    )


def test_runner_selection_is_deterministic():
    for label, config in _PRESET_CONFIGS:
        first = runners_pkg.select(config)
        second = runners_pkg.select(config)
        assert first is not None, f"{label}: no runner matched"
        assert first.id == second.id == runners_pkg.select(config).id


# --- Duplicate-id guards -----------------------------------------------------
# A second module (or a copy-pasted id within one module) claiming an id that
# already exists must raise, never silently overwrite the first registration.


def test_registering_duplicate_capability_id_raises():
    with pytest.raises(ValueError):
        registry.capability(
            id="pkce",  # already registered by catalog/pkce.py
            label="duplicate",
            description="duplicate",
            spec_ref=SpecRef(rfc="RFC 0000", section="§0"),
        )
    # The original registration must be untouched.
    assert registry.get("pkce") is not None
    assert registry.get("pkce").label == "PKCE"


def test_registering_duplicate_attack_id_raises():
    with pytest.raises(ValueError):
        registry.attack(
            id="auth_code_injection",  # already registered by catalog/auth_code_injection.py
            label="duplicate",
            description="duplicate",
            spec_ref=SpecRef(rfc="RFC 0000", section="§0"),
        )


def test_registering_duplicate_runner_id_raises():
    with pytest.raises(ValueError):
        runners_pkg.register(
            runners_pkg.Runner(
                id="happy_path",  # already registered by runners/happy_path.py
                matches=lambda config: False,
                run=lambda config: None,  # type: ignore[return-value]
            )
        )
    # The original registration must still be the one selected, unreplaced.
    happy = next(r for r in runners_pkg.all_runners() if r.id == "happy_path")
    assert happy.matches.__module__.endswith("happy_path")
    assert len([r for r in runners_pkg.all_runners() if r.id == "happy_path"]) == 1


# --- check_names coverage of shipped fixtures --------------------------------
# A capability that blocks a run should declare the check name it blocks with,
# in its own catalog file (RegistryItem.check_names). Walk every committed
# fixture and, wherever a verdict names a responsible_capability, assert the
# actual failing check at blocked_at_seq is declared under that capability —
# so a future capability that forgets to declare its check name is caught
# here, from real shipped traces, not just from a runner's own unit test.


def _by_id():
    return {i.id: i for i in [*registry.CAPABILITIES, *registry.ATTACKS]}


def _assert_attributed_block_is_declared(backend_id, trace, by_id, seen):
    cap_id = trace.verdict.responsible_capability
    if cap_id is None:
        return
    block = next(
        (e for e in trace.events if e.seq == trace.verdict.blocked_at_seq), None
    )
    assert block is not None and block.check is not None, (
        f"{backend_id}: verdict names responsible_capability {cap_id!r} but "
        "blocked_at_seq event carries no check"
    )
    seen.append((backend_id, block.check.name, cap_id))
    item = by_id.get(cap_id)
    assert item is not None, f"{backend_id}: responsible_capability {cap_id!r} is not registered"
    assert block.check.name in item.check_names, (
        f"{backend_id}: check {block.check.name!r} was attributed to {cap_id!r} "
        f"but is not declared in its catalog check_names ({item.check_names!r})"
    )


def test_check_names_cover_every_attributed_check_in_shipped_fixtures():
    by_id = _by_id()
    seen: list = []

    for backend_id, _frontend_name, _config in TRACE_FIXTURES:
        raw = json.loads((BACKEND_FIXTURES / f"{backend_id}.json").read_text())
        trace = trace_from_dict(raw)
        _assert_attributed_block_is_declared(backend_id, trace, by_id, seen)

    for backend_id, _frontend_name, _baseline, _variant in COMPARE_FIXTURES:
        raw = json.loads((BACKEND_FIXTURES / f"{backend_id}.json").read_text())
        for side in ("baseline", "variant"):
            trace = trace_from_dict(raw[side])
            _assert_attributed_block_is_declared(
                f"{backend_id}:{side}", trace, by_id, seen
            )

    # Guard against the test going vacuous (e.g. every fixture stops blocking).
    assert seen, "no shipped fixture attributed a block to a capability"
    # And sanity-check today's known pair so a silent rename is still visible.
    attributed = {(check, cap) for _fid, check, cap in seen}
    assert ("pkce_verifier_match", "pkce") in attributed
    assert ("state_matches_session", "state") in attributed
