"""Regenerate committed, generated artifacts from the source of truth.

Run from the backend directory:

    python -m scripts.regen

Regenerates:

- ``otv/contract_enums.json`` — the frozen enum tuples + ``SCHEMA_VERSION`` from
  :func:`otv.contract.enum_manifest`, used by the cross-language guard test to
  catch drift between ``contract.py`` and ``frontend/src/types/trace.ts``.
- ``otv/fixtures/happy_path_auth_code.json`` and the byte-identical frontend copy
  ``frontend/src/fixtures/happyPath.json`` — the committed golden trace, produced
  by a real happy-path run. Random values (codes, tokens, correlation id) change
  each regen; the fixture-drift test compares *structure*, not those values.

The trace is contract-validated before it is written, so a broken run can never
be committed as a fixture.
"""

from __future__ import annotations

import json
from pathlib import Path

from otv.contract import ScenarioConfig, enum_manifest, validate
from otv.engine.conductor import run

BACKEND = Path(__file__).resolve().parent.parent
REPO = BACKEND.parent
ENUMS_PATH = BACKEND / "otv" / "contract_enums.json"
BACKEND_FIXTURE = BACKEND / "otv" / "fixtures" / "happy_path_auth_code.json"
FRONTEND_FIXTURE = REPO / "frontend" / "src" / "fixtures" / "happyPath.json"


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def regen_enums() -> None:
    _write_json(ENUMS_PATH, enum_manifest())
    print(f"wrote {ENUMS_PATH.relative_to(REPO)}")


def regen_fixture() -> None:
    trace = run(ScenarioConfig(grant="authorization_code"))
    validate(trace)
    data = trace.to_dict()
    for path in (BACKEND_FIXTURE, FRONTEND_FIXTURE):
        _write_json(path, data)
        print(f"wrote {path.relative_to(REPO)}")


if __name__ == "__main__":
    regen_enums()
    regen_fixture()
