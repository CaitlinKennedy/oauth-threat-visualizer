"""Regenerate committed, generated artifacts from the source of truth.

Run from the backend directory:

    python -m scripts.regen

Regenerates:

- ``otv/contract_enums.json`` — the frozen enum tuples + ``SCHEMA_VERSION`` from
  :func:`otv.contract.enum_manifest`, used by the cross-language guard test to
  catch drift between ``contract.py`` and ``frontend/src/types/trace.ts``.
- The committed golden traces (and their byte-identical frontend copies): the
  happy path, the flow-2 injection (PKCE off, attacker wins), the flow-3
  injection (PKCE on, attacker blocked), and the flow-2↔3 compare/diff response.
  Each is produced by a real run. Random values (codes, tokens, correlation ids,
  signatures) change every regen; the fixture-drift test compares *structure*,
  not those values.

Every trace is contract-validated before it is written, so a broken run can never
be committed as a fixture.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from otv.contract import (
    FeatureState,
    ScenarioConfig,
    enum_manifest,
    validate,
    validate_compare_response,
)
from otv.engine.compare import run_compare
from otv.engine.conductor import run

BACKEND = Path(__file__).resolve().parent.parent
REPO = BACKEND.parent
ENUMS_PATH = BACKEND / "otv" / "contract_enums.json"
BACKEND_FIXTURES = BACKEND / "otv" / "fixtures"
FRONTEND_FIXTURES = REPO / "frontend" / "src" / "fixtures"

def _cfg(caps=None, atks=None, grant="authorization_code") -> ScenarioConfig:
    return ScenarioConfig(
        grant=grant,
        capabilities=caps or {},
        attacks=atks or {},
    )


# (backend fixture id, frontend basename, config) for the single-trace fixtures.
TRACE_FIXTURES: List[Tuple[str, str, ScenarioConfig]] = [
    ("happy_path_auth_code", "happyPath.json", _cfg()),
    (
        "injection_no_pkce",
        "injectionNoPkce.json",
        _cfg(
            caps={"pkce": FeatureState(active=False)},
            atks={"auth_code_injection": FeatureState(active=True)},
        ),
    ),
    (
        "injection_pkce",
        "injectionPkce.json",
        _cfg(
            caps={"pkce": FeatureState(active=True, params={"method": "S256"})},
            atks={"auth_code_injection": FeatureState(active=True)},
        ),
    ),
    (
        "csrf_no_state",
        "csrfNoState.json",
        _cfg(
            caps={"state": FeatureState(active=False)},
            atks={"csrf_code_injection": FeatureState(active=True)},
        ),
    ),
    (
        "csrf_state",
        "csrfState.json",
        _cfg(
            caps={"state": FeatureState(active=True)},
            atks={"csrf_code_injection": FeatureState(active=True)},
        ),
    ),
    (
        "replay",
        "replay.json",
        _cfg(atks={"code_token_replay": FeatureState(active=True)}),
    ),
    (
        "jwt_bearer_happy",
        "jwtBearerHappy.json",
        _cfg(grant="jwt_bearer"),
    ),
    (
        "assertion_replay_no_protection",
        "assertionReplayNoProtection.json",
        _cfg(
            grant="jwt_bearer",
            caps={"assertion_replay_protection": FeatureState(active=False)},
            atks={"assertion_replay": FeatureState(active=True)},
        ),
    ),
    (
        "assertion_replay_protected",
        "assertionReplayProtected.json",
        _cfg(
            grant="jwt_bearer",
            caps={"assertion_replay_protection": FeatureState(active=True)},
            atks={"assertion_replay": FeatureState(active=True)},
        ),
    ),
    # Phase 5 — client credentials + client authentication methods.
    (
        "client_credentials_secret",
        "clientCredentialsSecret.json",
        _cfg(
            grant="client_credentials",
            caps={
                "client_auth": FeatureState(
                    active=True, params={"method": "client_secret_basic"}
                )
            },
        ),
    ),
    (
        "client_credentials_jwt",
        "clientCredentialsJwt.json",
        _cfg(
            grant="client_credentials",
            caps={
                "client_auth": FeatureState(
                    active=True, params={"method": "private_key_jwt"}
                )
            },
        ),
    ),
    (
        "static_secret_leak_secret",
        "staticSecretLeakSecret.json",
        _cfg(
            grant="client_credentials",
            caps={
                "client_auth": FeatureState(
                    active=True, params={"method": "client_secret_basic"}
                )
            },
            atks={"static_secret_leak": FeatureState(active=True)},
        ),
    ),
    (
        "static_secret_leak_jwt",
        "staticSecretLeakJwt.json",
        _cfg(
            grant="client_credentials",
            caps={
                "client_auth": FeatureState(
                    active=True, params={"method": "private_key_jwt"}
                )
            },
            atks={"static_secret_leak": FeatureState(active=True)},
        ),
    ),
]

# The paired-diff fixtures (a CompareResponse each, not a Trace):
# (backend id, frontend basename, baseline config, variant config).
COMPARE_FIXTURES: List[Tuple[str, str, ScenarioConfig, ScenarioConfig]] = [
    (
        "injection_pkce_compare",
        "injectionCompare.json",
        _cfg(
            caps={"pkce": FeatureState(active=False)},
            atks={"auth_code_injection": FeatureState(active=True)},
        ),
        _cfg(
            caps={"pkce": FeatureState(active=True, params={"method": "S256"})},
            atks={"auth_code_injection": FeatureState(active=True)},
        ),
    ),
    (
        "csrf_state_compare",
        "csrfStateCompare.json",
        _cfg(
            caps={"state": FeatureState(active=False)},
            atks={"csrf_code_injection": FeatureState(active=True)},
        ),
        _cfg(
            caps={"state": FeatureState(active=True)},
            atks={"csrf_code_injection": FeatureState(active=True)},
        ),
    ),
    (
        "assertion_replay_compare",
        "assertionReplayCompare.json",
        _cfg(
            grant="jwt_bearer",
            caps={"assertion_replay_protection": FeatureState(active=False)},
            atks={"assertion_replay": FeatureState(active=True)},
        ),
        _cfg(
            grant="jwt_bearer",
            caps={"assertion_replay_protection": FeatureState(active=True)},
            atks={"assertion_replay": FeatureState(active=True)},
        ),
    ),
    (
        "client_auth_leak_compare",
        "clientAuthLeakCompare.json",
        _cfg(
            grant="client_credentials",
            caps={
                "client_auth": FeatureState(
                    active=True, params={"method": "client_secret_basic"}
                )
            },
            atks={"static_secret_leak": FeatureState(active=True)},
        ),
        _cfg(
            grant="client_credentials",
            caps={
                "client_auth": FeatureState(
                    active=True, params={"method": "private_key_jwt"}
                )
            },
            atks={"static_secret_leak": FeatureState(active=True)},
        ),
    ),
]


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _write_both(backend_id: str, frontend_name: str, data: Dict[str, Any]) -> None:
    for path in (
        BACKEND_FIXTURES / f"{backend_id}.json",
        FRONTEND_FIXTURES / frontend_name,
    ):
        _write_json(path, data)
        print(f"wrote {path.relative_to(REPO)}")


def regen_enums() -> None:
    _write_json(ENUMS_PATH, enum_manifest())
    print(f"wrote {ENUMS_PATH.relative_to(REPO)}")


def regen_fixtures() -> None:
    for backend_id, frontend_name, config in TRACE_FIXTURES:
        trace = run(config)
        validate(trace)
        _write_both(backend_id, frontend_name, trace.to_dict())

    for backend_id, frontend_name, baseline, variant in COMPARE_FIXTURES:
        resp = run_compare(baseline, variant)
        payload = resp.to_dict()
        validate_compare_response(payload)
        _write_both(backend_id, frontend_name, payload)


if __name__ == "__main__":
    regen_enums()
    regen_fixtures()
