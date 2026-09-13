"""Registry / catalog and config-wire-shape tests.

Lock down the open id-keyed config map, the reserved envelope fields, and the
serialized catalog the UI picker depends on.
"""

import pytest

from otv import registry
from otv.contract import (
    ContractError,
    FeatureState,
    ScenarioConfig,
    feature_map_from_dict,
    validate,
)
from otv.engine.conductor import run


def test_catalog_serializes_with_required_metadata():
    cat = registry.to_catalog_dict()
    assert cat["capabilities"] and cat["attacks"]
    for item in [*cat["capabilities"], *cat["attacks"]]:
        for key in (
            "id",
            "label",
            "description",
            "spec_ref",
            "kind",
            "phase",
            "default_active",
            "params",
            "incompatibilities",
            "applies_to_grants",
            "implies",
            "forbids",
            "available",
        ):
            assert key in item, f"catalog item missing {key}"
        assert item["spec_ref"]["rfc"] and item["spec_ref"]["section"]
        for list_key in ("applies_to_grants", "implies", "forbids"):
            assert isinstance(item[list_key], list)
    ids = {i["id"] for i in cat["capabilities"]}
    assert {"pkce", "state", "dpop"} <= ids


def test_catalog_phase_numbers_match_the_roadmap():
    cat = registry.to_catalog_dict()
    by_id = {i["id"]: i for i in [*cat["capabilities"], *cat["attacks"]]}
    expected = {
        "pkce": 1,
        "auth_code_injection": 1,
        "state": 2,
        "code_token_replay": 2,
        "static_secret_leak": 5,
        "dpop": 6,
        "issuer_id": 7,
        "phish_then_inject": 7,
    }
    for fid, phase in expected.items():
        assert by_id[fid]["phase"] == phase, f"{fid} phase should be {phase}"


def test_applies_to_grants_populated_sensibly():
    by_id = {i.id: i for i in [*registry.CAPABILITIES, *registry.ATTACKS]}
    assert by_id["pkce"].applies_to_grants == ["authorization_code"]
    assert by_id["state"].applies_to_grants == ["authorization_code"]
    assert by_id["dpop"].applies_to_grants == []  # applies broadly


def test_availability_reflects_current_phase():
    cat = registry.to_catalog_dict()
    by_id = {i["id"]: i for i in [*cat["capabilities"], *cat["attacks"]]}
    # Phase 2 makes pkce + auth-code injection, plus state / replay / CSRF,
    # runnable; nothing later yet.
    available = {i["id"] for i in [*cat["capabilities"], *cat["attacks"]] if i["available"]}
    assert available == {
        "pkce",
        "auth_code_injection",
        "state",
        "code_token_replay",
        "csrf_code_injection",
    }
    # And availability is exactly "phase <= CURRENT_PHASE".
    for item in by_id.values():
        assert item["available"] == (item["phase"] <= registry.CURRENT_PHASE)


def test_feature_map_accepts_state_objects_and_bool_shorthand():
    m = feature_map_from_dict({"pkce": {"active": True, "params": {"method": "S256"}}})
    assert m["pkce"].active is True
    assert m["pkce"].params == {"method": "S256"}
    coerced = feature_map_from_dict({"state": True})
    assert coerced["state"] == FeatureState(active=True)


def test_config_is_an_open_id_keyed_map_not_bools():
    d = run(ScenarioConfig(grant="authorization_code")).to_dict()
    assert isinstance(d["config"]["capabilities"], dict)
    assert isinstance(d["config"]["attacks"], dict)


def test_reserved_envelope_fields_present_and_null():
    d = run(ScenarioConfig(grant="authorization_code")).to_dict()
    assert "parent_id" in d and d["parent_id"] is None
    assert "chain_id" in d and d["chain_id"] is None


def test_validator_rejects_bare_bool_capability_on_the_wire():
    d = run(ScenarioConfig(grant="authorization_code")).to_dict()
    d["config"]["capabilities"] = {"pkce": True}  # not a state object
    with pytest.raises(ContractError):
        validate(d)
