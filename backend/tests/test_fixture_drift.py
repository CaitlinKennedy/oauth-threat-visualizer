"""Fixture-drift guard.

The committed golden trace (``otv/fixtures/happy_path_auth_code.json``, mirrored
byte-for-byte in ``frontend/src/fixtures/happyPath.json``) must stay structurally
identical to a fresh live happy-path run. Random values (codes, tokens,
correlation id, signatures) differ every run, so this compares *structure* —
seq/actor/phase/outcome/summary, each step's check, the highlight paths, and the
diagram source/target — not those values.

If this fails after an intentional emitter change, regenerate the fixtures with
``python -m scripts.regen``.
"""

import json
from pathlib import Path

from otv.contract import ScenarioConfig
from otv.engine.conductor import run

BACKEND = Path(__file__).resolve().parent.parent
REPO = BACKEND.parent
BACKEND_FIXTURE = BACKEND / "otv" / "fixtures" / "happy_path_auth_code.json"
FRONTEND_FIXTURE = REPO / "frontend" / "src" / "fixtures" / "happyPath.json"


def _skeleton(trace: dict) -> list:
    """The structural fingerprint of a trace, free of run-specific random values."""
    skel = []
    for e in trace["events"]:
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
                "check": {"name": check.get("name"), "result": check.get("result")}
                if check
                else None,
                "highlight": http.get("highlight"),
                "source_actor": http.get("source_actor"),
                "target_actor": http.get("target_actor"),
            }
        )
    return skel


def test_live_run_matches_committed_fixture_structure():
    live = run(ScenarioConfig(grant="authorization_code")).to_dict()
    committed = json.loads(BACKEND_FIXTURE.read_text())
    assert _skeleton(live) == _skeleton(committed), (
        "live happy-path structure diverged from the committed fixture — "
        "run `python -m scripts.regen`"
    )


def test_backend_and_frontend_fixtures_are_byte_identical():
    assert json.loads(BACKEND_FIXTURE.read_text()) == json.loads(
        FRONTEND_FIXTURE.read_text()
    ), "backend and frontend fixtures diverged — run `python -m scripts.regen`"
