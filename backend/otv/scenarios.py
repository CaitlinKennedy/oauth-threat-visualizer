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
    {
        "id": "csrf_no_state",
        "flow": 4,
        "name": "CSRF code injection (no state)",
        "tagline": "Whose session does the code belong to?",
        "description": (
            "The attacker obtains a valid authorization code for their own account on "
            "the victim's client, then delivers it into the victim's browser. With no "
            "'state' check the victim's client redeems the attacker's code and is bound "
            "to the attacker's account — the classic login-CSRF."
        ),
        "config": {
            "grant": "authorization_code",
            "capabilities": {"state": {"active": False}},
            "attacks": {"csrf_code_injection": {"active": True, "params": {}}},
        },
        "available": True,
    },
    {
        "id": "csrf_state",
        "flow": 4,
        "name": "CSRF defeated by state",
        "tagline": "Why bind the response to the session?",
        "description": (
            "The identical injection now fails: the injected code arrives without the "
            "'state' the victim's client generated, so the client rejects the response "
            "before redeeming it. This is why 'state' (or PKCE, which also binds the "
            "response) is required against CSRF."
        ),
        "config": {
            "grant": "authorization_code",
            "capabilities": {"state": {"active": True}},
            "attacks": {"csrf_code_injection": {"active": True, "params": {}}},
        },
        "available": True,
    },
    {
        # The flow-2↔3 gesture for CSRF: flip 'state' and watch the injection go
        # from a successful cross-session binding to a block at the state check.
        "id": "csrf_state_compare",
        "flow": 4,
        "mode": "compare",
        "name": "Flip state: CSRF blocked vs. not",
        "tagline": "Watch the one step where state decides the outcome.",
        "description": (
            "Runs the same cross-session code injection with 'state' off and 'state' "
            "on, side by side, and marks the single step where the two runs diverge."
        ),
        "config": {
            "grant": "authorization_code",
            "capabilities": {"state": {"active": True}},
            "attacks": {"csrf_code_injection": {"active": True, "params": {}}},
        },
        "compare": {
            "baseline": {
                "grant": "authorization_code",
                "capabilities": {"state": {"active": False}},
                "attacks": {"csrf_code_injection": {"active": True, "params": {}}},
            },
            "variant": {
                "grant": "authorization_code",
                "capabilities": {"state": {"active": True}},
                "attacks": {"csrf_code_injection": {"active": True, "params": {}}},
            },
        },
        "available": True,
    },
    {
        "id": "replay",
        "flow": 5,
        "name": "Auth-code replay defeated by single use",
        "tagline": "Can a captured code be used twice?",
        "description": (
            "The honest client completes a real redemption, then the attacker replays "
            "the very same code. The second redemption fails at the single-use check in "
            "the code store — a captured authorization code is worthless once spent."
        ),
        "config": {
            "grant": "authorization_code",
            "capabilities": {},
            "attacks": {"code_token_replay": {"active": True, "params": {}}},
        },
        "available": True,
    },
    {
        "id": "jwt_bearer_happy",
        "flow": 6,
        "name": "JWT bearer grant — happy path",
        "tagline": "A user-scoped token with no browser, redirect, or consent.",
        "description": (
            "A client presents a real signed JWT assertion (sub = the user) directly "
            "to the token endpoint and receives a user-scoped access token. There is no "
            "front channel at all — so auth-code injection, redirect CSRF and mix-up "
            "have nothing to target. The trust now rests on the signing key and the "
            "assertion instead."
        ),
        "config": {
            "grant": "jwt_bearer",
            "capabilities": {},
            "attacks": {},
        },
        "available": True,
    },
    {
        "id": "token_replay_bearer",
        "flow": 6,
        "name": "Token replay (plain bearer)",
        "tagline": "Can a stolen access token be reused?",
        "description": (
            "The honest client obtains an access token and reads its resource. The "
            "attacker steals a copy of the token and replays it at the resource "
            "server. With a plain bearer token, possession is all that is required — "
            "the attacker reads the victim's resource."
        ),
        "config": {
            "grant": "authorization_code",
            "capabilities": {"dpop": {"active": False}},
            "attacks": {"token_replay": {"active": True, "params": {}}},
        },
        "available": True,
    },
    {
        "id": "client_credentials_secret",
        "flow": 1,
        "name": "Client credentials (machine-to-machine)",
        "tagline": "OAuth with no user at all.",
        "description": (
            "The client-credentials grant: no user, no browser, no redirect. The "
            "client authenticates directly at the token endpoint with a client secret "
            "and the authorization server issues a token whose subject is the CLIENT "
            "itself — the machine-to-machine contrast with the user-based grants."
        ),
        "config": {
            "grant": "client_credentials",
            "capabilities": {
                "client_auth": {"active": True, "params": {"method": "client_secret_basic"}}
            },
            "attacks": {},
        },
        "available": True,
    },
    {
        "id": "assertion_replay_no_protection",
        "flow": 6,
        "name": "Assertion replay (no protection)",
        "tagline": "The trust relocated — now it can be replayed.",
        "description": (
            "The attacker captures a still-valid assertion off the back channel and "
            "replays it at the token endpoint. With no replay protection the server "
            "honors the reused assertion and issues the attacker a user-scoped token: "
            "the counter-lesson that removing the front channel does not remove all "
            "risk, it moves it onto the assertion."
        ),
        "config": {
            "grant": "jwt_bearer",
            "capabilities": {"assertion_replay_protection": {"active": False}},
            "attacks": {"assertion_replay": {"active": True, "params": {}}},
        },
        "available": True,
    },
    {
        "id": "token_replay_dpop",
        "flow": 6,
        "name": "Token replay defeated by DPoP",
        "tagline": "Why bind the token to a key?",
        "description": (
            "The identical theft now fails: the token is sender-constrained via "
            "cnf.jkt, so the resource server requires a DPoP proof from the bound "
            "key. The attacker holds the token but not the client's private key, so "
            "the key-binding check rejects the replay. This is why DPoP defeats token "
            "theft at the resource server."
        ),
        "config": {
            "grant": "authorization_code",
            "capabilities": {"dpop": {"active": True}},
            "attacks": {"token_replay": {"active": True, "params": {}}},
        },
        "available": True,
    },
    {
        "id": "client_credentials_jwt",
        "flow": 1,
        "name": "Client credentials with private_key_jwt",
        "tagline": "Prove identity with a key, not a secret.",
        "description": (
            "The same machine-to-machine flow, but the client authenticates with a "
            "signed private_key_jwt assertion instead of a shared secret. The "
            "authorization server holds only the client's public key, so no static "
            "credential ever transits the wire."
        ),
        "config": {
            "grant": "client_credentials",
            "capabilities": {
                "client_auth": {"active": True, "params": {"method": "private_key_jwt"}}
            },
            "attacks": {},
        },
        "available": True,
    },
    {
        "id": "assertion_replay_protected",
        "flow": 6,
        "name": "Assertion replay defeated by one-time jti",
        "tagline": "Why an assertion is bound to key + audience + time + a single use.",
        "description": (
            "The identical replay now fails: the assertion's signature and claims still "
            "verify, but its jti was already redeemed and one-time use is enforced (with "
            "a short exp and aud=token endpoint behind it). The attacker cannot mint a "
            "fresh assertion because it lacks the issuer's signing key."
        ),
        "config": {
            "grant": "jwt_bearer",
            "capabilities": {"assertion_replay_protection": {"active": True}},
            "attacks": {"assertion_replay": {"active": True, "params": {}}},
        },
        "available": True,
    },
    {
        "id": "static_secret_leak_secret",
        "flow": 2,
        "name": "Static-secret leak (attacker wins)",
        "tagline": "A leaked secret that never rotates.",
        "description": (
            "The client's static client_secret leaks and the attacker replays it. "
            "Because a shared static secret IS the client's authority and never "
            "rotates, the attacker authenticates as the client and mints its own "
            "token — permanent impersonation."
        ),
        "config": {
            "grant": "client_credentials",
            "capabilities": {
                "client_auth": {"active": True, "params": {"method": "client_secret_basic"}}
            },
            "attacks": {"static_secret_leak": {"active": True, "params": {}}},
        },
        "available": True,
    },
    {
        # The flow-2↔3 gesture for the JWT bearer grant: flip replay protection and
        # watch the replay go from a user-scoped token for the attacker to a block at
        # the one-time jti check.
        "id": "assertion_replay_compare",
        "flow": 6,
        "mode": "compare",
        "name": "Flip replay protection: replay blocked vs. not",
        "tagline": "Watch the one step where one-time jti decides the outcome.",
        "description": (
            "Runs the same assertion replay with replay protection off and on, side by "
            "side, and marks the single step where the two runs diverge — the token "
            "endpoint's one-time jti check on the replayed assertion."
        ),
        "config": {
            "grant": "jwt_bearer",
            "capabilities": {"assertion_replay_protection": {"active": True}},
            "attacks": {"assertion_replay": {"active": True, "params": {}}},
        },
        "compare": {
            "baseline": {
                "grant": "jwt_bearer",
                "capabilities": {"assertion_replay_protection": {"active": False}},
                "attacks": {"assertion_replay": {"active": True, "params": {}}},
            },
            "variant": {
                "grant": "jwt_bearer",
                "capabilities": {"assertion_replay_protection": {"active": True}},
                "attacks": {"assertion_replay": {"active": True, "params": {}}},
            },
        },
        "available": True,
    },
    {
        "id": "static_secret_leak_jwt",
        "flow": 3,
        "name": "Static-secret leak defeated by private_key_jwt",
        "tagline": "Why bind client identity to a key?",
        "description": (
            "The identical leak now fails: with private_key_jwt there is no static "
            "secret to steal. The most an attacker can capture is a spent, short-lived "
            "client_assertion, which fails real signature/expiry verification on "
            "replay — and a fresh one cannot be forged without the client's private "
            "key."
        ),
        "config": {
            "grant": "client_credentials",
            "capabilities": {
                "client_auth": {"active": True, "params": {"method": "private_key_jwt"}}
            },
            "attacks": {"static_secret_leak": {"active": True, "params": {}}},
        },
        "available": True,
    },
    {
        # The flow-2↔3 gesture for client authentication: run the identical leak with
        # a static secret vs. private_key_jwt, side by side, and mark the step where
        # the two runs diverge (the client-authentication check that decides it).
        "id": "client_auth_leak_compare",
        "flow": 3,
        "mode": "compare",
        "name": "Flip client auth: leak wins vs. defeated",
        "tagline": "Watch the one step where the auth method decides the outcome.",
        "description": (
            "Runs the same static-secret leak with client_secret_basic and with "
            "private_key_jwt, side by side, and marks the client-authentication step "
            "where the attacker's replay is accepted in one run and rejected in the "
            "other."
        ),
        "config": {
            "grant": "client_credentials",
            "capabilities": {
                "client_auth": {"active": True, "params": {"method": "private_key_jwt"}}
            },
            "attacks": {"static_secret_leak": {"active": True, "params": {}}},
        },
        "compare": {
            "baseline": {
                "grant": "client_credentials",
                "capabilities": {
                    "client_auth": {"active": True, "params": {"method": "client_secret_basic"}}
                },
                "attacks": {"static_secret_leak": {"active": True, "params": {}}},
            },
            "variant": {
                "grant": "client_credentials",
                "capabilities": {
                    "client_auth": {"active": True, "params": {"method": "private_key_jwt"}}
                },
                "attacks": {"static_secret_leak": {"active": True, "params": {}}},
            },
        },
        "available": True,
    },
    {
        # The flow-2↔3 gesture for DPoP: flip 'dpop' and watch the stolen token go
        # from a successful read to a block at the resource server's key binding.
        "id": "token_replay_compare",
        "flow": 6,
        "mode": "compare",
        "name": "Flip DPoP: token replay blocked vs. not",
        "tagline": "Watch the one step where DPoP decides the outcome.",
        "description": (
            "Runs the same access-token replay with DPoP off and DPoP on, side by "
            "side, and marks the step where the two runs diverge — the resource "
            "server's DPoP key-binding check."
        ),
        "config": {
            "grant": "authorization_code",
            "capabilities": {"dpop": {"active": True}},
            "attacks": {"token_replay": {"active": True, "params": {}}},
        },
        "compare": {
            "baseline": {
                "grant": "authorization_code",
                "capabilities": {"dpop": {"active": False}},
                "attacks": {"token_replay": {"active": True, "params": {}}},
            },
            "variant": {
                "grant": "authorization_code",
                "capabilities": {"dpop": {"active": True}},
                "attacks": {"token_replay": {"active": True, "params": {}}},
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
