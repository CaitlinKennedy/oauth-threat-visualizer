"""API-level tests for the Flask control plane.

Locks the hardened ``/api/run`` behaviour (never a 500 for bad input, never a
fake happy-path success for a scenario the caller didn't request) and the routing
fixes for unknown API paths and missing assets.
"""

import pytest

from app import create_app


@pytest.fixture()
def client():
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_catalog_exposes_new_fields_and_phases(client):
    cat = client.get("/api/catalog").get_json()
    by_id = {i["id"]: i for i in [*cat["capabilities"], *cat["attacks"]]}
    for item in by_id.values():
        for key in ("applies_to_grants", "implies", "forbids", "available"):
            assert key in item
    # Corrected phase numbers (IMPLEMENTATION.md §6–§7).
    assert by_id["pkce"]["phase"] == 1
    assert by_id["state"]["phase"] == 2
    assert by_id["static_secret_leak"]["phase"] == 5
    assert by_id["dpop"]["phase"] == 6
    assert by_id["issuer_id"]["phase"] == 7
    assert by_id["pkce"]["applies_to_grants"] == ["authorization_code"]
    # CURRENT_PHASE = 0 → nothing is available yet.
    assert all(not i["available"] for i in by_id.values())


def test_run_happy_path_returns_live_trace(client):
    r = client.post("/api/run", json={"config": {"grant": "authorization_code"}})
    assert r.status_code == 200
    body = r.get_json()
    assert body["schema_version"] == "1.0"
    assert body["verdict"]["user_got_token"] is True
    assert "_source" not in body  # a real live run, not the fixture fallback


@pytest.mark.parametrize(
    "payload",
    [
        {"config": None},
        [1, 2],
        {"config": {"capabilities": {"pkce": 5}}},
        "not-json-object",
    ],
)
def test_run_malformed_body_is_400_json_not_500(client, payload):
    r = client.post("/api/run", json=payload)
    assert r.status_code == 400
    assert r.get_json()["error"] == "bad_request"


def test_run_unsupported_config_is_not_a_fake_success(client):
    # A grant that isn't implemented must NOT return a happy-path success.
    r = client.post("/api/run", json={"config": {"grant": "client_credentials"}})
    assert r.status_code == 501
    body = r.get_json()
    assert body["error"] == "not_available"
    assert body["mode"] == "unsupported"
    assert "verdict" not in body


def test_run_unsupported_capability_is_flagged(client):
    r = client.post(
        "/api/run",
        json={
            "config": {
                "grant": "authorization_code",
                "capabilities": {"pkce": {"active": True}},
            }
        },
    )
    assert r.status_code == 501
    assert r.get_json()["error"] == "not_available"


def test_unknown_api_route_is_json_404(client):
    r = client.get("/api/nope")
    assert r.status_code == 404
    assert r.get_json()["error"] == "not_found"


def test_missing_asset_with_extension_is_404(client):
    r = client.get("/foo/assets/does-not-exist.js")
    assert r.status_code == 404
