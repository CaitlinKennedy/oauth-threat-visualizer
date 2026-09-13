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
        "description": (
            "The attacker captures the victim's authorization code from the front "
            "channel and redeems it at the token endpoint. With no PKCE, a valid code "
            "is all that is required — the attacker obtains a token for the victim."
        ),
        "config": {
            "grant": "authorization_code",
            "capabilities": {"pkce": {"active": False}},
            "attacks": {"auth_code_injection": {"active": True, "params": {}}},
        },
        "available": True,
    },
    {
        "id": "injection_pkce",
        "flow": 3,
        "name": "Auth-code injection defeated by PKCE",
        "tagline": "Why is this mitigation required?",
        "description": (
            "The identical attack now fails: the attacker holds the code but not the "
            "code_verifier, so the S256 check at the token endpoint rejects the "
            "exchange. This is why OAuth 2.1 makes PKCE mandatory."
        ),
        "config": {
            "grant": "authorization_code",
            "capabilities": {"pkce": {"active": True, "params": {"method": "S256"}}},
            "attacks": {"auth_code_injection": {"active": True, "params": {}}},
        },
        "available": True,
    },
    {
        # The primary gesture (DESIGN.md §8): flip PKCE and watch flow 2 and flow 3
        # stay identical until they diverge at the verifier check. Carries the two
        # configs so the UI can drive the paired-diff endpoint directly.
        "id": "injection_pkce_compare",
        "flow": 3,
        "mode": "compare",
        "name": "Flip PKCE: injection blocked vs. not",
        "tagline": "Watch the one step where PKCE decides the outcome.",
        "description": (
            "Runs the same auth-code injection with PKCE off and PKCE on, side by "
            "side, and marks the single step where the two runs diverge."
        ),
        "config": {
            "grant": "authorization_code",
            "capabilities": {"pkce": {"active": True, "params": {"method": "S256"}}},
            "attacks": {"auth_code_injection": {"active": True, "params": {}}},
        },
        "compare": {
            "baseline": {
                "grant": "authorization_code",
                "capabilities": {"pkce": {"active": False}},
                "attacks": {"auth_code_injection": {"active": True, "params": {}}},
            },
            "variant": {
                "grant": "authorization_code",
                "capabilities": {"pkce": {"active": True, "params": {"method": "S256"}}},
                "attacks": {"auth_code_injection": {"active": True, "params": {}}},
            },
        },
        "available": True,
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
