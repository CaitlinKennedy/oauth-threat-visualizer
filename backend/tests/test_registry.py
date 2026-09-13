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
            "available",
        ):
            assert key in item, f"catalog item missing {key}"
        assert item["spec_ref"]["rfc"] and item["spec_ref"]["section"]
    ids = {i["id"] for i in cat["capabilities"]}
    assert {"pkce", "state", "dpop"} <= ids


def test_no_feature_is_available_in_phase_0():
    cat = registry.to_catalog_dict()
    # Phase 0 exercises only the authorization_code grant; every catalogued
    # capability/attack toggle arrives in a later phase.
    assert all(not i["available"] for i in [*cat["capabilities"], *cat["attacks"]])


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
