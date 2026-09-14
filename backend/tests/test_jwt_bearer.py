"""Phase 4 tests: the JWT bearer grant (RFC 7523) and assertion replay.

These lock the Phase 4 pedagogical core:

- The happy path exchanges a signed assertion for a *real*, verifiable access
  token with no front channel at all (no authorize/redirect phase).
- Because there is no front channel, the front-channel attacks are Not Applicable
  to this grant (scoped away by ``applies_to_grants``), and other grants / later
  phases stay conductor-rejected.
- Assertion replay is blocked by the genuine one-time-``jti`` check, with the
  responsible capability derived from the failing check via the registry; without
  the protection the replay wins and reads the user's profile.
- The protection off-vs-on paired diff diverges at exactly the ``jti`` check.
- The new catalog items are available in Phase 4; Phase 5+ items are not.
"""

import jwt
import pytest

from otv import crypto, registry
from otv.actors.environment import Environment
from otv.contract import (
    FeatureState,
    ScenarioConfig,
    validate,
    validate_compare_response,
)
from otv.engine.compare import _fingerprint, run_compare
from otv.engine.conductor import UnsupportedScenario, run
from otv.engine.runners.support import CHECK_TO_CAPABILITY


def _cfg(caps=None, atks=None) -> ScenarioConfig:
    return ScenarioConfig(
        grant="jwt_bearer",
        capabilities={k: FeatureState(**v) for k, v in (caps or {}).items()},
        attacks={k: FeatureState(**v) for k, v in (atks or {}).items()},
    )


def _replay(protection: bool) -> ScenarioConfig:
    return _cfg(
        caps={"assertion_replay_protection": {"active": protection}},
        atks={"assertion_replay": {"active": True}},
    )


# --- Happy path: a real token, and no front channel -------------------------


@pytest.fixture()
def happy_trace():
    return run(_cfg())


def test_happy_path_verdict(happy_trace):
    v = happy_trace.verdict
    assert v.user_got_token is True
    assert v.user_accessed_resource is True
    assert v.attacker_got_token is False
    assert v.blocked_at_seq is None
    assert v.responsible_capability is None


def test_happy_path_has_no_front_channel(happy_trace):
    """The whole point: no authorize/redirect phase, no attacker, no consent step."""
    phases = {e.phase for e in happy_trace.events}
    assert phases <= {"token", "resource"}
    assert "authorize" not in phases and "redirect" not in phases
    assert all(e.actor != "attacker" for e in happy_trace.events)
    assert all(e.on_behalf_of == "user" for e in happy_trace.events)


def test_happy_path_assertion_and_token_checks_pass(happy_trace):
    checks = {e.check.name: e.check for e in happy_trace.events if e.check}
    assert set(checks) == {
        "assertion_signature_and_claims",
        "assertion_jti_single_use",
        "access_token_validation",
    }
    assert all(c.result == "PASS" for c in checks.values())


def test_happy_path_issues_a_real_verifiable_token(happy_trace):
    """The token the RS honored must actually verify against the AS's JWKS."""
    token = None
    for e in happy_trace.events:
        if (
            e.http
            and isinstance(e.http.response.body, dict)
            and "access_token" in e.http.response.body
        ):
            token = e.http.response.body["access_token"]
    assert token, "no access token found in the trace"

    env = Environment()
    # A real signature: verifying against the WRONG key must fail ...
    wrong_key = crypto.SigningKey.generate()
    with pytest.raises(jwt.PyJWTError):
        crypto.verify_access_token(
            token, jwks=wrong_key.jwks(), issuer=env.issuer, audience=env.resource_audience
        )
    # ... and the claims are scoped to the user named in the assertion's sub.
    claims = crypto.decode_claims_unverified(token)
    assert claims["iss"] == env.issuer
    assert claims["aud"] == env.resource_audience
    assert claims["sub"] == env.user.sub


def test_assertion_is_a_real_signed_jwt_bound_to_the_token_endpoint():
    """The assertion the client mints is genuinely signed and audience-bound."""
    trace = run(_cfg())
    assertion_claims = None
    for e in trace.events:
        if (
            e.actor == "client"
            and e.http
            and isinstance(e.http.response.body, dict)
            and "jti" in e.http.response.body
        ):
            assertion_claims = e.http.response.body
    assert assertion_claims is not None
    env = Environment()
    # aud must be the token endpoint (so it cannot be presented elsewhere).
    assert assertion_claims["aud"] == env.token_url
    assert assertion_claims["sub"] == env.user.sub


# --- Front-channel attacks are N/A for this grant ---------------------------


def test_front_channel_attacks_are_not_applicable_to_jwt_bearer():
    """The front-channel attacks are scoped to the auth-code grant, so the
    data-driven picker never offers them for jwt_bearer — they have no front
    channel to target here."""
    for aid in ("auth_code_injection", "csrf_code_injection"):
        item = registry.get(aid)
        assert item is not None
        assert item.applies_to_grants == ["authorization_code"]
        assert "jwt_bearer" not in item.applies_to_grants
    # The residual attack, by contrast, is scoped to this grant.
    assert registry.get("assertion_replay").applies_to_grants == ["jwt_bearer"]


def test_other_grants_and_later_phase_features_still_rejected():
    # A Phase 5 attack stays refused even at CURRENT_PHASE 4.
    with pytest.raises(UnsupportedScenario):
        run(_cfg(atks={"static_secret_leak": {"active": True}}))
    # The client-credentials grant has no runner yet.
    with pytest.raises(UnsupportedScenario):
        run(ScenarioConfig(grant="client_credentials"))


# --- Assertion replay: blocked by the real one-time-jti check ---------------


def test_replay_blocked_when_protection_on():
    trace = run(_replay(protection=True))
    validate(trace)
    v = trace.verdict
    assert v.attacker_got_token is False
    assert v.user_got_token is True  # the honest exchange completed first
    assert isinstance(v.blocked_at_seq, int)
    assert v.responsible_capability == "assertion_replay_protection"
    assert v.responsible_capabilities == ["assertion_replay_protection"]

    block = next(e for e in trace.events if e.seq == v.blocked_at_seq)
    assert block.check is not None
    assert block.check.name == "assertion_jti_single_use"
    assert block.check.result == "FAIL"
    assert block.outcome == "attack_blocked"
    # The honest redemption's jti check passed; the replay's failed.
    jti_results = [
        e.check.result for e in trace.events if e.check and e.check.name == "assertion_jti_single_use"
    ]
    assert jti_results == ["PASS", "FAIL"]
    # The assertion signature/claims verify BOTH times — replay is the only issue.
    sig_results = [
        e.check.result
        for e in trace.events
        if e.check and e.check.name == "assertion_signature_and_claims"
    ]
    assert sig_results == ["PASS", "PASS"]
    # The attacker's terminal step is a first-class attack_blocked.
    assert any(e.actor == "attacker" and e.outcome == "attack_blocked" for e in trace.events)


def test_replay_block_is_derived_from_the_trace_not_hardcoded():
    """responsible_capability must come from the failing check via the registry map."""
    trace = run(_replay(protection=True))
    block = next(e for e in trace.events if e.seq == trace.verdict.blocked_at_seq)
    assert CHECK_TO_CAPABILITY[block.check.name] == trace.verdict.responsible_capability


def test_replay_wins_when_protection_off_and_reads_the_user_profile():
    trace = run(_replay(protection=False))
    validate(trace)
    v = trace.verdict
    assert v.attacker_got_token is True
    assert v.user_got_token is True
    assert v.blocked_at_seq is None
    assert v.responsible_capability is None
    # A first-class attack_success step, and the replayed-flow token reads the
    # user's protected profile (the impact).
    assert any(e.outcome == "attack_success" for e in trace.events)
    served = [
        e.http.response.body
        for e in trace.events
        if e.actor == "resource_server"
        and e.http
        and isinstance(e.http.response.body, dict)
        and "username" in e.http.response.body
    ]
    assert served and served[-1]["username"] == Environment().user.username


def test_attacker_knowledge_lacks_the_signing_key():
    trace = run(_replay(protection=True))
    capture = next(
        e for e in trace.events if e.actor == "attacker" and "attacker" in e.knowledge_delta
    )
    ks = capture.knowledge_delta["attacker"]
    assert "jwt_assertion" in ks.has
    assert "assertion_signing_key" in ks.lacks


# --- Compare: the protection off-vs-on divergence ---------------------------


def test_compare_diverges_at_the_jti_check():
    resp = run_compare(_replay(protection=False), _replay(protection=True))
    validate_compare_response(resp)
    assert resp.divergences, "expected a non-empty divergences list"
    first = resp.divergences[0]
    assert first.reason == "assertion_jti_single_use"
    assert first.capability == "assertion_replay_protection"
    # The runs are genuinely different either side of the divergence.
    assert any(e.outcome == "attack_success" for e in resp.baseline.events)
    assert resp.variant.verdict.responsible_capability == "assertion_replay_protection"


def test_compare_prefix_identical_until_divergence():
    resp = run_compare(_replay(protection=False), _replay(protection=True))
    div_seq = resp.divergences[0].seq
    b = {e.seq: e for e in resp.baseline.events}
    v = {e.seq: e for e in resp.variant.events}
    for seq in range(1, div_seq):
        assert _fingerprint(b[seq]) == _fingerprint(v[seq]), f"step {seq} should match"
    assert _fingerprint(b[div_seq]) != _fingerprint(v[div_seq])


# --- Catalog metadata --------------------------------------------------------


def test_new_phase4_items_available_and_scoped():
    by_id = {
        i["id"]: i
        for i in [
            *registry.to_catalog_dict()["capabilities"],
            *registry.to_catalog_dict()["attacks"],
        ]
    }
    for fid in ("assertion_replay_protection", "assertion_replay"):
        assert by_id[fid]["available"] is True
        assert by_id[fid]["phase"] == 4
        assert by_id[fid]["applies_to_grants"] == ["jwt_bearer"]
    # The protection capability declares the check it blocks with.
    assert registry.get("assertion_replay_protection").check_names == [
        "assertion_jti_single_use"
    ]
