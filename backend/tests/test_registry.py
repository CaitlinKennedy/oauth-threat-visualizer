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
            "default_active",
            "params",
            "incompatibilities",
            "applies_to_grants",
            "implies",
            "forbids",
        ):
            assert key in item, f"catalog item missing {key}"
        # Feature gating is gone: the catalog just lists features.
        assert "phase" not in item and "available" not in item
        assert item["spec_ref"]["rfc"] and item["spec_ref"]["section"]
        for list_key in ("applies_to_grants", "implies", "forbids"):
            assert isinstance(item[list_key], list)
    ids = {i["id"] for i in cat["capabilities"]}
    assert {"pkce", "state", "dpop"} <= ids


def test_catalog_lists_exactly_the_shipped_features():
    cat = registry.to_catalog_dict()
    cap_ids = [i["id"] for i in cat["capabilities"]]
    atk_ids = [i["id"] for i in cat["attacks"]]
    # Every shipped capability/attack is listed, and nothing deferred lingers.
    assert set(cap_ids) == {
        "pkce",
        "state",
        "assertion_replay_protection",
        "client_auth",
        "dpop",
    }
    assert set(atk_ids) == {
        "auth_code_injection",
        "code_token_replay",
        "csrf_code_injection",
        "assertion_replay",
        "static_secret_leak",
        "token_replay",
    }


def test_applies_to_grants_populated_sensibly():
    by_id = {i.id: i for i in [*registry.CAPABILITIES, *registry.ATTACKS]}
    assert by_id["pkce"].applies_to_grants == ["authorization_code"]
    assert by_id["state"].applies_to_grants == ["authorization_code"]
    assert by_id["dpop"].applies_to_grants == []  # applies broadly


def test_unknown_feature_is_rejected_by_the_conductor():
    # A registered feature is simply available; an id that isn't in the registry
    # is refused rather than silently ignored.
    from otv.contract import FeatureState
    from otv.engine.conductor import UnsupportedScenario

    with pytest.raises(UnsupportedScenario):
        run(
            ScenarioConfig(
                grant="authorization_code",
                capabilities={"no_such_capability": FeatureState(active=True)},
            )
        )
    assert registry.get("no_such_capability") is None


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
