"""Scenario presets — named, ready-made run configs for the learning flows.

The capability/attack *catalog* lives in :mod:`otv.registry` (served by
``GET /api/catalog``); this module holds the presets that map to the four
learning flows (served by ``GET /api/scenarios``). Each preset is a ready-made
``RunConfig`` in the frozen open-map wire shape. Only flow 1 (the clean
authorization-code happy path) is runnable in Phase 0; later flows are listed
with ``available: false`` so the roadmap is visible.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .contract import ScenarioConfig, feature_map_from_dict

HAPPY_PATH_ID = "happy_path_auth_code"

PRESETS: List[Dict[str, Any]] = [
    {
        "id": HAPPY_PATH_ID,
        "flow": 1,
        "name": "Authorization Code — happy path",
        "tagline": "How does OAuth actually work?",
        "description": (
            "A clean authorization-code run with no attacker activity. Establishes the "
            "mental model: redirect to the authorization server, consent, a single-use "
            "code, a back-channel exchange for a signed token, and a validated API call."
        ),
        "config": {
            "grant": "authorization_code",
            "capabilities": {},
            "attacks": {},
        },
        "available": True,
    },
    {
        "id": "injection_no_pkce",
        "flow": 2,
        "name": "Auth-code injection (no mitigation)",
        "tagline": "What does the attacker see and do?",
        "description": "The attacker injects a stolen code and wins. Arrives in Phase 1.",
        "config": {
            "grant": "authorization_code",
            "capabilities": {"pkce": {"active": False}},
            "attacks": {"auth_code_injection": {"active": True, "params": {}}},
        },
        "available": False,
    },
    {
        "id": "injection_pkce",
        "flow": 3,
        "name": "Auth-code injection defeated by PKCE",
        "tagline": "Why is this mitigation required?",
        "description": "The same attack now fails at the verifier check. Arrives in Phase 1.",
        "config": {
            "grant": "authorization_code",
            "capabilities": {"pkce": {"active": True, "params": {"method": "S256"}}},
            "attacks": {"auth_code_injection": {"active": True, "params": {}}},
        },
        "available": False,
    },
]


def default_preset() -> Dict[str, Any]:
    return next(p for p in PRESETS if p["id"] == HAPPY_PATH_ID)


def config_from_dict(d: Dict[str, Any]) -> ScenarioConfig:
    """Parse a RunConfig from the open-map wire shape."""
    return ScenarioConfig(
        grant=d.get("grant", "authorization_code"),
        capabilities=feature_map_from_dict(d.get("capabilities", {})),
        attacks=feature_map_from_dict(d.get("attacks", {})),
    )


def presets_payload() -> Dict[str, Any]:
    """The payload for ``GET /api/scenarios``."""
    return {"presets": PRESETS, "default_preset": HAPPY_PATH_ID}
