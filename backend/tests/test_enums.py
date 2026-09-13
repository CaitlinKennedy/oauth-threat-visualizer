"""Cross-language enum guard (A8).

The frozen enums live in three places that must never drift:

- ``otv.contract`` (the Python source of truth),
- ``otv/contract_enums.json`` (a committed, generated manifest), and
- ``frontend/src/types/trace.ts`` (the TypeScript mirror the UI compiles against).

These tests assert all three agree — including the duplicated ``SCHEMA_VERSION``,
which is the single value most prone to silent skew. Regenerate the JSON with
``python -m scripts.regen`` after an intentional enum change.
"""

import json
import re
from pathlib import Path

from otv.contract import enum_manifest

BACKEND = Path(__file__).resolve().parent.parent
REPO = BACKEND.parent
ENUMS_JSON = BACKEND / "otv" / "contract_enums.json"
TRACE_TS = REPO / "frontend" / "src" / "types" / "trace.ts"

ENUM_NAMES = ("ACTORS", "PHASES", "OUTCOMES", "CHECK_RESULTS", "GRANTS")


def _parse_ts_array(source: str, name: str) -> list[str]:
    m = re.search(rf"export const {name}\s*=\s*\[(.*?)\]", source, re.DOTALL)
    assert m, f"could not find `export const {name} = [...]` in trace.ts"
    return re.findall(r'"([^"]+)"', m.group(1))


def _parse_ts_scalar(source: str, name: str) -> str:
    m = re.search(rf'export const {name}\s*=\s*"([^"]+)"', source)
    assert m, f"could not find `export const {name} = \"...\"` in trace.ts"
    return m.group(1)


def test_committed_enums_json_matches_python_source():
    committed = json.loads(ENUMS_JSON.read_text())
    assert committed == enum_manifest(), (
        "contract_enums.json is stale — run `python -m scripts.regen`"
    )


def test_trace_ts_enums_match_the_manifest():
    manifest = enum_manifest()
    ts = TRACE_TS.read_text()
    assert _parse_ts_scalar(ts, "SCHEMA_VERSION") == manifest["SCHEMA_VERSION"]
    for name in ENUM_NAMES:
        assert _parse_ts_array(ts, name) == manifest[name], f"{name} differs from contract.py"
