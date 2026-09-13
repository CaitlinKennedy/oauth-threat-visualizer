"""Fixture-drift guard.

Every committed golden trace (in ``otv/fixtures/``, each mirrored byte-for-byte
in ``frontend/src/fixtures/``) must stay structurally identical to a fresh live
run of its scenario. Random values (codes, tokens, correlation id, signatures)
differ every run, so this compares *structure* — seq/actor/phase/outcome/summary,
the causal ``refs`` graph, each step's check, the highlight paths, and the
diagram source/target — not those values.

The fixture set is imported from ``scripts.regen`` so this guard and the
regenerator never drift apart. If this fails after an intentional emitter change,
regenerate the fixtures with ``python -m scripts.regen``.
"""

import json
from pathlib import Path

import pytest

from otv.engine.compare import run_compare
from otv.engine.conductor import run
from scripts.regen import (
    COMPARE_BASELINE,
    COMPARE_FIXTURE,
    COMPARE_VARIANT,
    TRACE_FIXTURES,
)

BACKEND = Path(__file__).resolve().parent.parent
REPO = BACKEND.parent
BACKEND_FIXTURES = BACKEND / "otv" / "fixtures"
FRONTEND_FIXTURES = REPO / "frontend" / "src" / "fixtures"


def _skeleton(events: list) -> list:
    """The structural fingerprint of an event list, free of random values."""
    skel = []
    for e in events:
        http = e.get("http") or {}
        check = e.get("check") or {}
        skel.append(
            {
                "seq": e["seq"],
                "actor": e["actor"],
                "actor_instance": e.get("actor_instance"),
                "phase": e["phase"],
                "outcome": e["outcome"],
                "summary": e["summary"],
                "on_behalf_of": e["on_behalf_of"],
                # The causal graph is load-bearing (the UI teaches from it), so the
                # exact refs are part of the structural fingerprint, not incidental.
                "refs": e.get("refs"),
                "check": {"name": check.get("name"), "result": check.get("result")}
                if check
                else None,
                "highlight": http.get("highlight"),
                "source_actor": http.get("source_actor"),
                "target_actor": http.get("target_actor"),
            }
        )
    return skel


@pytest.mark.parametrize(
    "backend_id,frontend_name,config",
    TRACE_FIXTURES,
    ids=[f[0] for f in TRACE_FIXTURES],
)
def test_live_run_matches_committed_trace_fixture(backend_id, frontend_name, config):
    live = run(config).to_dict()
    committed = json.loads((BACKEND_FIXTURES / f"{backend_id}.json").read_text())
    assert _skeleton(live["events"]) == _skeleton(committed["events"]), (
        f"{backend_id}: live structure diverged from the committed fixture — "
        "run `python -m scripts.regen`"
    )


@pytest.mark.parametrize(
    "backend_id,frontend_name",
    [(b, f) for b, f, _ in TRACE_FIXTURES] + [COMPARE_FIXTURE],
    ids=[f[0] for f in TRACE_FIXTURES] + [COMPARE_FIXTURE[0]],
)
def test_backend_and_frontend_fixtures_are_byte_identical(backend_id, frontend_name):
    backend = json.loads((BACKEND_FIXTURES / f"{backend_id}.json").read_text())
    frontend = json.loads((FRONTEND_FIXTURES / frontend_name).read_text())
    assert backend == frontend, (
        f"{backend_id}: backend and frontend fixtures diverged — "
        "run `python -m scripts.regen`"
    )


def test_live_compare_matches_committed_compare_fixture():
    live = run_compare(COMPARE_BASELINE, COMPARE_VARIANT).to_dict()
    committed = json.loads((BACKEND_FIXTURES / f"{COMPARE_FIXTURE[0]}.json").read_text())
    assert _skeleton(live["baseline"]["events"]) == _skeleton(
        committed["baseline"]["events"]
    )
    assert _skeleton(live["variant"]["events"]) == _skeleton(
        committed["variant"]["events"]
    )
    assert live["divergences"] == committed["divergences"], (
        "compare divergences drifted — run `python -m scripts.regen`"
    )
