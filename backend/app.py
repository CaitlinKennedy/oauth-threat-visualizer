"""Flask application: the control-plane API plus the built UI.

Endpoints (IMPLEMENTATION.md §5):

- ``GET  /api/health``        liveness
- ``GET  /api/scenarios``     presets + capability/attack catalog metadata
- ``POST /api/run``           run a scenario config; returns the materialized Trace
- ``GET  /api/fixtures/<id>`` a committed golden trace (demo / fallback)
- ``GET  /*``                 serves the built React app from ``static/``

``POST /api/run`` runs the real actors; if a live run raises (or the config is
outside the current phase), it falls back to the committed golden trace so the
UI always receives a complete, contract-valid trace.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from flask import Flask, jsonify, request, send_from_directory

from otv import registry, scenarios
from otv.contract import trace_from_dict, validate
from otv.engine.conductor import UnsupportedScenario, run

FIXTURES_DIR = Path(__file__).parent / "otv" / "fixtures"
STATIC_DIR = Path(__file__).parent / "static"

# The fixture used as the fallback for the happy-path preset / an empty config.
DEFAULT_FIXTURE_ID = "happy_path_auth_code"


def _load_fixture(fixture_id: str) -> Optional[Dict[str, Any]]:
    safe = os.path.basename(fixture_id)  # prevent path traversal
    path = FIXTURES_DIR / f"{safe}.json"
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "schema_version": __import__("otv").SCHEMA_VERSION})

    @app.get("/api/catalog")
    def get_catalog():
        # The typed registry serialized: capabilities + attacks with metadata.
        # The UI picker renders from this, so it never changes when a feature is
        # added.
        return jsonify(registry.to_catalog_dict())

    @app.get("/api/scenarios")
    def get_scenarios():
        # Named presets mapping to the learning flows.
        return jsonify(scenarios.presets_payload())

    @app.get("/api/fixtures/<fixture_id>")
    def get_fixture(fixture_id: str):
        data = _load_fixture(fixture_id)
        if data is None:
            return jsonify({"error": "not_found", "fixture": fixture_id}), 404
        return jsonify(data)

    @app.post("/api/run")
    def post_run():
        body = request.get_json(silent=True) or {}
        raw_config = body.get("config", body)  # accept {config:{...}} or a bare config
        config = scenarios.config_from_dict(raw_config)
        try:
            trace = run(config)
            return jsonify(trace.to_dict())
        except UnsupportedScenario:
            # Outside the implemented phase: serve the committed golden trace so
            # the UI still demos a complete, correct flow (same contract shape).
            return _fixture_response(DEFAULT_FIXTURE_ID, source="fallback")
        except Exception:  # a live run failed unexpectedly — degrade gracefully
            app.logger.exception("live run failed; serving fixture fallback")
            return _fixture_response(DEFAULT_FIXTURE_ID, source="fallback")

    def _fixture_response(fixture_id: str, *, source: str):
        data = _load_fixture(fixture_id)
        if data is None:
            return jsonify({"error": "no_fixture", "fixture": fixture_id}), 500
        validate(trace_from_dict(data))  # never serve a broken fallback
        data = dict(data)
        data["_source"] = source
        return jsonify(data)

    # --- Static UI (built Vite app copied into static/) --------------------

    @app.get("/")
    def index():
        return _serve_ui("index.html")

    @app.get("/<path:path>")
    def catch_all(path: str):
        # Serve a real static asset if it exists; otherwise fall back to the SPA
        # entry point so client-side routing works.
        asset = STATIC_DIR / path
        if asset.is_file():
            return _serve_ui(path)
        return _serve_ui("index.html")

    def _serve_ui(path: str):
        index_path = STATIC_DIR / "index.html"
        if not index_path.is_file():
            return (
                jsonify(
                    {
                        "message": "OAuth Threat Visualizer API is running. "
                        "The UI has not been built into static/ in this environment.",
                        "api": ["/api/health", "/api/scenarios", "/api/run", "/api/fixtures/<id>"],
                    }
                ),
                200,
            )
        return send_from_directory(STATIC_DIR, path)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), debug=True)
