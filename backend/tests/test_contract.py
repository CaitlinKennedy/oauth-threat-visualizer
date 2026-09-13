"""Contract-validator tests.

Every emitted trace — live and committed — must validate against the frozen
schema and carry the current ``SCHEMA_VERSION``. These tests also exercise the
validator's negative paths so the guard itself cannot silently rot.
"""

import copy
import json
from pathlib import Path

import pytest

from otv.contract import (
    SCHEMA_VERSION,
    ContractError,
    ScenarioConfig,
    trace_from_dict,
    validate,
)
from otv.engine.conductor import run

FIXTURES_DIR = Path(__file__).parent.parent / "otv" / "fixtures"


def _run_happy():
    return run(ScenarioConfig(grant="authorization_code"))


def test_live_trace_validates():
    trace = _run_happy()
    validate(trace)  # raises on any violation
    assert trace.schema_version == SCHEMA_VERSION


def test_live_trace_dict_roundtrips_and_validates():
    d = _run_happy().to_dict()
    assert d["schema_version"] == SCHEMA_VERSION
    validate(d)  # dict form
    validate(trace_from_dict(d))  # rehydrated form


def test_committed_fixture_validates():
    path = FIXTURES_DIR / "happy_path_auth_code.json"
    data = json.loads(path.read_text())
    assert data["schema_version"] == SCHEMA_VERSION
    validate(trace_from_dict(data))


def test_seqs_are_strictly_increasing_and_refs_point_backward():
    d = _run_happy().to_dict()
    seqs = [e["seq"] for e in d["events"]]
    assert seqs == sorted(seqs)
    assert len(seqs) == len(set(seqs))
    for e in d["events"]:
        for r in e["refs"]:
            assert r < e["seq"]


def test_validator_rejects_wrong_schema_version():
    d = _run_happy().to_dict()
    d["schema_version"] = "0.9"
    with pytest.raises(ContractError):
        validate(d)


def test_validator_rejects_unknown_actor():
    d = _run_happy().to_dict()
    d["events"][0]["actor"] = "wizard"
    with pytest.raises(ContractError):
        validate(d)


def test_validator_rejects_bad_outcome():
    d = _run_happy().to_dict()
    d["events"][0]["outcome"] = "maybe"
    with pytest.raises(ContractError):
        validate(d)


def test_validator_rejects_forward_ref():
    d = _run_happy().to_dict()
    d["events"][0]["refs"] = [9999]
    with pytest.raises(ContractError):
        validate(d)


def test_validator_rejects_empty_events():
    d = _run_happy().to_dict()
    d["events"] = []
    with pytest.raises(ContractError):
        validate(d)
