"""Phase 2 tests: state enforcement, CSRF injection, and auth-code replay.

These lock the Phase 2 pedagogical core:

- ``state`` is ENFORCED when active (a mismatch is rejected before redemption) and
  merely REPORTED when inactive (the P1 honest-report behavior).
- CSRF / cross-session code injection succeeds without ``state`` (the victim's
  client is bound to the attacker's account) and is blocked with ``state`` on —
  the responsible capability and blocked seq derived from the emitted trace.
- Auth-code replay fails at the genuine single-use check on the second redemption.
- The ``state`` off-vs-on paired diff diverges at the state check.
- The catalog is unchanged for the existing items and the new items are available.
"""

import pytest

from otv import registry
from otv.actors.client import ClientImpl
from otv.actors.environment import Environment
from otv.contract import FeatureState, ScenarioConfig, validate, validate_compare_response
from otv.engine.compare import run_compare
from otv.engine.conductor import run
from otv.recorder import Recorder
from otv.trace_context import acting


def _cfg(caps=None, atks=None) -> ScenarioConfig:
    return ScenarioConfig(
        grant="authorization_code",
        capabilities={k: FeatureState(**v) for k, v in (caps or {}).items()},
        attacks={k: FeatureState(**v) for k, v in (atks or {}).items()},
    )


def _csrf(state: bool) -> ScenarioConfig:
    return _cfg(
        caps={"state": {"active": state}},
        atks={"csrf_code_injection": {"active": True}},
    )


# --- state: enforced when active, honest-report when inactive ----------------


def test_state_enforced_when_active_blocks_on_mismatch():
    env = Environment()
    recorder = Recorder("run_test", ScenarioConfig(grant="authorization_code"))
    client = ClientImpl(recorder, env, enforce_state=True)
    with acting(on_behalf_of="user"):
        client.start_authorization()
        received = client.receive_redirect({"code": "ac_x", "state": "not-the-state"})
    assert received["state_ok"] is False
    assert received["blocked"] is True  # enforced → the client stops
    ev = next(e for e in recorder.events if e.check and e.check.name == "state_matches_session")
    assert ev.check.result == "FAIL"
    assert ev.outcome == "attack_blocked"


def test_state_honest_report_when_inactive_does_not_block():
    env = Environment()
    recorder = Recorder("run_test", ScenarioConfig(grant="authorization_code"))
    client = ClientImpl(recorder, env, enforce_state=False)
    with acting(on_behalf_of="user"):
        client.start_authorization()
        received = client.receive_redirect({"code": "ac_x", "state": "not-the-state"})
    assert received["state_ok"] is False
    assert received["blocked"] is False  # inactive → reported but not enforced
    ev = next(e for e in recorder.events if e.check and e.check.name == "state_matches_session")
    assert ev.check.result == "FAIL"
    assert ev.outcome == "blocked"  # honest report, not attack_blocked


def test_state_match_is_ok_regardless_of_enforcement():
    for enforce in (True, False):
        env = Environment()
        recorder = Recorder("run_test", ScenarioConfig(grant="authorization_code"))
        client = ClientImpl(recorder, env, enforce_state=enforce)
        with acting(on_behalf_of="user"):
            started = client.start_authorization()
            received = client.receive_redirect(
                {"code": "ac_x", "state": started["params"]["state"]}
            )
        assert received["state_ok"] is True
        assert received["blocked"] is False


# --- CSRF: succeeds without state, blocked with state -----------------------


def test_csrf_without_state_succeeds_as_cross_session_binding():
    trace = run(_csrf(state=False))
    validate(trace)
    v = trace.verdict
    # The attacker did not steal the victim's token; the harm is the reverse
    # binding (login CSRF), surfaced as a first-class attack_success step.
    assert v.attacker_got_token is False
    assert v.blocked_at_seq is None
    success = [e for e in trace.events if e.outcome == "attack_success"]
    assert success, "expected a cross-session binding attack_success step"
    # The token the victim's client redeemed is bound to the ATTACKER's account:
    # the resource server serves the attacker's profile, not the victim's.
    served = [
        e.http.response.body
        for e in trace.events
        if e.actor == "resource_server"
        and e.http
        and isinstance(e.http.response.body, dict)
        and "username" in e.http.response.body
    ]
    assert served and served[-1]["username"] == "mallory"


def test_csrf_with_state_is_blocked_at_the_state_check():
    trace = run(_csrf(state=True))
    validate(trace)
    v = trace.verdict
    assert v.attacker_got_token is False
    assert v.responsible_capability == "state"
    assert v.responsible_capabilities == ["state"]
    assert isinstance(v.blocked_at_seq, int)

    # The block is a genuine FAIL of the state check, and the verdict points at it.
    block = next(e for e in trace.events if e.seq == v.blocked_at_seq)
    assert block.check is not None
    assert block.check.name == "state_matches_session"
    assert block.check.result == "FAIL"
    assert block.outcome == "attack_blocked"
    # No token is ever redeemed in the blocked run.
    assert not any(e.actor == "resource_server" for e in trace.events)


def test_csrf_block_is_derived_from_the_trace_not_hardcoded():
    """responsible_capability must come from the failing check via the registry map."""
    from otv.engine.runners.support import CHECK_TO_CAPABILITY

    trace = run(_csrf(state=True))
    block = next(e for e in trace.events if e.seq == trace.verdict.blocked_at_seq)
    assert CHECK_TO_CAPABILITY[block.check.name] == trace.verdict.responsible_capability


def test_csrf_attacker_knowledge_lacks_the_victim_session_state():
    trace = run(_csrf(state=True))
    stage = next(
        e for e in trace.events if e.actor == "attacker" and "attacker" in e.knowledge_delta
    )
    ks = stage.knowledge_delta["attacker"]
    assert "victim_session_state" in ks.lacks


# --- replay: single-use defeats the second redemption ----------------------


def test_replay_user_wins_attacker_blocked_at_single_use():
    trace = run(_cfg(atks={"code_token_replay": {"active": True}}))
    validate(trace)
    v = trace.verdict
    assert v.user_got_token is True
    assert v.user_accessed_resource is True
    assert v.attacker_got_token is False
    assert isinstance(v.blocked_at_seq, int)

    # The block is the single-use check FAILing on the SECOND redemption.
    block = next(e for e in trace.events if e.seq == v.blocked_at_seq)
    assert block.check is not None
    assert block.check.name == "authorization_code_single_use"
    assert block.check.result == "FAIL"
    # Single use is intrinsic, not a toggleable capability, so nothing is named.
    assert v.responsible_capability is None
    # The single-use check passes for the honest redemption and fails for the replay.
    single_use_results = [
        e.check.result
        for e in trace.events
        if e.check and e.check.name == "authorization_code_single_use"
    ]
    assert single_use_results == ["PASS", "FAIL"]
    # The attacker's terminal step is a first-class attack_blocked.
    assert any(e.actor == "attacker" and e.outcome == "attack_blocked" for e in trace.events)


# --- compare: the state off-vs-on divergence -------------------------------


def test_csrf_compare_diverges_at_the_state_check():
    resp = run_compare(_csrf(state=False), _csrf(state=True))
    validate_compare_response(resp)
    assert resp.divergences, "expected a non-empty divergences list"
    first = resp.divergences[0]
    assert first.reason == "state_matches_session"
    assert first.capability == "state"
    # The runs are genuinely different either side of the divergence.
    off = resp.baseline.verdict
    on = resp.variant.verdict
    assert any(e.outcome == "attack_success" for e in resp.baseline.events)
    assert on.responsible_capability == "state"


def test_csrf_compare_prefix_identical_until_divergence():
    from otv.engine.compare import _fingerprint

    resp = run_compare(_csrf(state=False), _csrf(state=True))
    div_seq = resp.divergences[0].seq
    b = {e.seq: e for e in resp.baseline.events}
    v = {e.seq: e for e in resp.variant.events}
    for seq in range(1, div_seq):
        assert _fingerprint(b[seq]) == _fingerprint(v[seq]), f"step {seq} should match"
    assert _fingerprint(b[div_seq]) != _fingerprint(v[div_seq])


# --- catalog: existing items unchanged, new items available ----------------


def test_new_phase2_items_are_available_others_still_not():
    by_id = {i["id"]: i for i in [*registry.to_catalog_dict()["capabilities"],
                                  *registry.to_catalog_dict()["attacks"]]}
    # Runnable in Phase 2 (and still runnable now).
    for fid in ("state", "code_token_replay", "csrf_code_injection"):
        assert by_id[fid]["available"] is True, f"{fid} should be available"
    # Still on the roadmap after Phase 5 (dpop=6, issuer_id/phish_then_inject=7).
    for fid in ("dpop", "issuer_id", "phish_then_inject"):
        assert by_id[fid]["available"] is False, f"{fid} should not be available yet"
    # Availability is exactly phase <= CURRENT_PHASE.
    for item in by_id.values():
        assert item["available"] == (item["phase"] <= registry.CURRENT_PHASE)


def test_csrf_catalog_entry_metadata():
    item = registry.get("csrf_code_injection")
    assert item is not None
    assert item.kind == "attack"
    assert item.phase == 2
    assert item.applies_to_grants == ["authorization_code"]
    assert item.spec_ref.rfc == "RFC 6749"


def test_existing_catalog_items_metadata_unchanged():
    by_id = {i.id: i for i in [*registry.CAPABILITIES, *registry.ATTACKS]}
    assert by_id["pkce"].phase == 1
    assert by_id["pkce"].applies_to_grants == ["authorization_code"]
    assert by_id["state"].phase == 2
    assert by_id["state"].applies_to_grants == ["authorization_code"]
    assert by_id["code_token_replay"].phase == 2
    assert by_id["dpop"].phase == 6 and by_id["dpop"].applies_to_grants == []
