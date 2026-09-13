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
from werkzeug.exceptions import HTTPException

from otv import registry, scenarios
from otv.contract import (
    ContractError,
    ScenarioConfig,
    trace_from_dict,
    validate,
    validate_compare_response,
)
from otv.engine.compare import run_compare
from otv.engine.conductor import UnsupportedScenario, run

FIXTURES_DIR = Path(__file__).parent / "otv" / "fixtures"
STATIC_DIR = Path(__file__).parent / "static"

# The fixture used as the fallback for the happy-path config only (never for a
# scenario the user did not request — see the /api/run handler).
DEFAULT_FIXTURE_ID = "happy_path_auth_code"


def _load_fixture(fixture_id: str) -> Optional[Dict[str, Any]]:
    safe = os.path.basename(fixture_id)  # prevent path traversal
    path = FIXTURES_DIR / f"{safe}.json"
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _is_happy_path_config(config: ScenarioConfig) -> bool:
    """The clean authorization-code flow with no active capability or attack.

    This is the only config the happy-path fixture legitimately stands in for, so
    a live crash on *this* config may fall back to the fixture while any other
    config gets an explicit error instead of a fake success.
    """
    return (
        config.grant == "authorization_code"
        and not config.active_capabilities()
        and not config.active_attacks()
    )


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)

    # Reject oversized request bodies before they reach a handler (Werkzeug raises
    # RequestEntityTooLarge, a 413, which the error handler below turns into JSON). A
    # RunConfig is a small JSON object, so 256 KB is generous headroom.
    app.config["MAX_CONTENT_LENGTH"] = 256 * 1024

    @app.errorhandler(Exception)
    def handle_error(err: Exception):
        # Werkzeug's own HTTP errors (404 from an unmatched route, 413 over the body
        # cap, etc.) carry a code + name/description — surface those as JSON in the
        # same {"error", "message"} shape the rest of this file uses, rather than
        # Werkzeug's default HTML error page.
        if isinstance(err, HTTPException):
            return jsonify({"error": err.name, "message": err.description}), err.code
        # Anything else is a genuine bug: log the traceback and never leak internals.
        app.logger.exception("unhandled exception")
        return jsonify({"error": "internal_error", "message": "unexpected server error"}), 500

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
        # Parse and validate the request body *inside* error handling so malformed
        # input yields a JSON 400, never an HTML 500 (ADD-2).
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"error": "bad_request", "message": "body must be a JSON object"}), 400

        # Paired-diff form: {"compare": {"baseline": <config>, "variant": <config>}}.
        # Runs both and returns {mode, baseline, variant, divergences, divergence}.
        if isinstance(body.get("compare"), dict):
            return _run_compare(body["compare"])

        raw_config = body.get("config", body)  # accept {config:{...}} or a bare config
        if not isinstance(raw_config, dict):
            return jsonify({"error": "bad_request", "message": "config must be an object"}), 400
        try:
            config = scenarios.config_from_dict(raw_config)
        except (ContractError, ValueError, TypeError) as exc:
            return jsonify({"error": "bad_request", "message": str(exc)}), 400

        is_happy = _is_happy_path_config(config)
        try:
            trace = run(config)
            return jsonify(trace.to_dict())
        except UnsupportedScenario as exc:
            # An expected, well-understood gap: this scenario is not implemented in
            # this build. Say so explicitly — never a fake happy-path success.
            return (
                jsonify(
                    {
                        "mode": "unsupported",
                        "error": "not_available",
                        "message": str(exc),
                        "config": raw_config,
                    }
                ),
                501,
            )
        except Exception as exc:  # a genuine, unexpected live-run crash
            app.logger.exception("live run crashed")
            if is_happy:
                # The requested scenario *is* the happy path, so the committed
                # golden trace is a faithful stand-in.
                return _fixture_response(DEFAULT_FIXTURE_ID, source="fallback")
            # Otherwise surface the crash distinctly — do not fake success.
            return (
                jsonify(
                    {"mode": "error", "error": "run_failed", "message": str(exc)}
                ),
                500,
            )

    def _run_compare(compare: Dict[str, Any]):
        """Run a baseline + variant that differ by one toggle; return the diff."""
        baseline_raw = compare.get("baseline")
        variant_raw = compare.get("variant")
        if not isinstance(baseline_raw, dict) or not isinstance(variant_raw, dict):
            return (
                jsonify(
                    {
                        "error": "bad_request",
                        "message": "compare needs object 'baseline' and 'variant' configs",
                    }
                ),
                400,
            )
        try:
            baseline_cfg = scenarios.config_from_dict(baseline_raw)
            variant_cfg = scenarios.config_from_dict(variant_raw)
        except (ContractError, ValueError, TypeError) as exc:
            return jsonify({"error": "bad_request", "message": str(exc)}), 400
        try:
            resp = run_compare(baseline_cfg, variant_cfg)
        except UnsupportedScenario as exc:
            return (
                jsonify(
                    {"mode": "unsupported", "error": "not_available", "message": str(exc)}
                ),
                501,
            )
        except Exception as exc:  # a genuine, unexpected live-run crash
            app.logger.exception("compare run crashed")
            return jsonify({"mode": "error", "error": "run_failed", "message": str(exc)}), 500
        payload = resp.to_dict()
        validate_compare_response(payload)  # never hand the UI a broken diff
        return jsonify(payload)

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
        # Unknown API routes must not masquerade as the SPA: return a JSON 404 so a
        # mistyped endpoint fails loudly instead of returning index.html (ADD-6).
        if path == "api" or path.startswith("api/"):
            return jsonify({"error": "not_found", "path": f"/{path}"}), 404
        # Serve a real static asset if it exists.
        asset = STATIC_DIR / path
        if asset.is_file():
            return _serve_ui(path)
        # A path that names a file (has an extension) but doesn't exist is a real
        # 404 — don't hand back index.html for a missing .js/.css/etc.
        if os.path.splitext(path)[1]:
            return jsonify({"error": "not_found", "path": f"/{path}"}), 404
        # Otherwise it's a client-side route: serve the SPA entry point.
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
    # Bind to loopback by default and keep the Werkzeug debugger OFF unless
    # explicitly opted in via FLASK_DEBUG — the interactive debugger is
    # remote-code-execution-adjacent if exposed. Production uses gunicorn (see the
    # Dockerfile), which does not run this block.
    debug = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes", "on")
    host = os.environ.get("HOST", "127.0.0.1")
    app.run(host=host, port=int(os.environ.get("PORT", "8000")), debug=debug)
