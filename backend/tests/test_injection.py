"""Real PKCE and the auth-code injection flows (flows 2 & 3).

These lock the pedagogical core: the same attack succeeds without PKCE and fails
*at the real verifier check* with PKCE, the block is attributed to the pkce
capability, the attacker's knowledge shows it holds the code but lacks the
verifier, and the paired-diff pinpoints the divergence at the PKCE check.
"""

import pytest

from otv import crypto
from otv.contract import FeatureState, ScenarioConfig, validate, validate_compare_response
from otv.engine.compare import run_compare
from otv.engine.conductor import run


# --- PKCE crypto: real S256, PASS and FAIL ---------------------------------


def test_pkce_correct_verifier_matches():
    verifier = crypto.new_code_verifier()
    challenge = crypto.code_challenge_for(verifier, "S256")
    assert crypto.verify_pkce(verifier, challenge, "S256") is True


def test_pkce_wrong_verifier_fails():
    challenge = crypto.code_challenge_for(crypto.new_code_verifier(), "S256")
    other = crypto.new_code_verifier()
    assert crypto.verify_pkce(other, challenge, "S256") is False


def test_pkce_missing_verifier_fails():
    challenge = crypto.code_challenge_for(crypto.new_code_verifier(), "S256")
    assert crypto.verify_pkce(None, challenge, "S256") is False
    assert crypto.verify_pkce("", challenge, "S256") is False


def test_s256_challenge_is_the_real_rfc7636_construction():
    # RFC 7636 §4.2: BASE64URL(SHA256(ASCII(verifier))) with no padding.
    import base64
    import hashlib

    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"  # RFC 7636 appendix B
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode()
    assert crypto.code_challenge_for(verifier, "S256") == expected


# --- scenarios -------------------------------------------------------------


def _injection(pkce: bool) -> ScenarioConfig:
    caps = {"pkce": FeatureState(active=pkce, params={"method": "S256"} if pkce else {})}
    return ScenarioConfig(
        grant="authorization_code",
        capabilities=caps,
        attacks={"auth_code_injection": FeatureState(active=True)},
    )


def test_injection_without_pkce_attacker_wins():
    trace = run(_injection(pkce=False))
    validate(trace)
    v = trace.verdict
    assert v.attacker_got_token is True
    assert v.blocked_at_seq is None
    assert v.responsible_capability is None
    # The attacker's terminal step is a first-class attack_success.
    outcomes = [e.outcome for e in trace.events if e.actor == "attacker"]
    assert "attack_success" in outcomes
    # No PKCE check is emitted when PKCE is off.
    assert not any(e.check and e.check.name == "pkce_verifier_match" for e in trace.events)


def test_injection_with_pkce_is_blocked_by_the_real_check():
    trace = run(_injection(pkce=True))
    validate(trace)
    v = trace.verdict
    assert v.attacker_got_token is False
    assert v.responsible_capability == "pkce"
    assert v.responsible_capabilities == ["pkce"]
    assert isinstance(v.blocked_at_seq, int)

    # The block is a genuine FAIL of the pkce_verifier_match check, and the verdict
    # points at that exact seq.
    pkce_check = next(e for e in trace.events if e.check and e.check.name == "pkce_verifier_match")
    assert pkce_check.check.result == "FAIL"
    assert pkce_check.check.rule == "S256(code_verifier) == code_challenge"
    assert pkce_check.check.spec_ref.rfc == "RFC 7636"
    assert pkce_check.check.spec_ref.section == "§4.6"
    assert pkce_check.check.expected != pkce_check.check.actual  # real hashes differ
    assert v.blocked_at_seq == pkce_check.seq
    # No token is ever issued in the blocked run.
    assert not any(e.actor == "attacker" and e.outcome == "attack_success" for e in trace.events)


def test_attacker_knowledge_shows_code_but_not_verifier():
    trace = run(_injection(pkce=True))
    intercept = next(
        e for e in trace.events if e.actor == "attacker" and "attacker" in e.knowledge_delta
    )
    ks = intercept.knowledge_delta["attacker"]
    assert "authorization_code" in ks.has
    assert "code_verifier" in ks.lacks
    # Public-client scenario: the attacker never holds a client secret/credentials.
    assert "client_credentials" not in ks.has
    assert "client_secret" not in ks.has


@pytest.mark.parametrize("pkce", [False, True])
def test_injection_uses_public_client_and_no_secret(pkce):
    """PKCE must be the lone gate: a public client, and no client secret anywhere."""
    trace = run(_injection(pkce=pkce))
    seen_client_ids = set()
    for e in trace.events:
        body = e.http.request.body if (e.http and isinstance(e.http.request.body, dict)) else {}
        if "client_id" in body:
            seen_client_ids.add(body["client_id"])
        # No step's request body may carry a client secret.
        assert "client_secret" not in body, f"client_secret leaked at seq {e.seq}"
    assert seen_client_ids == {"demo-native-app"}
    # A public client is not authenticated, so there is no client_authentication check.
    assert not any(e.check and e.check.name == "client_authentication" for e in trace.events)
    # The public-client step is recorded honestly (informational, not a gate).
    assert any(
        e.actor == "auth_server" and "public client" in e.summary.lower() for e in trace.events
    )


def test_injection_highlights_the_decisive_token_params():
    trace = run(_injection(pkce=True))
    receive = next(
        e
        for e in trace.events
        if e.actor == "auth_server"
        and e.phase == "token"
        and e.summary.startswith("Token endpoint receives")
    )
    assert receive.http.highlight == ["request.body.code", "request.body.code_verifier"]
    assert receive.http.source_actor == "attacker"
    assert receive.http.target_actor == "auth_server"


def test_injection_refs_are_causally_truthful_not_just_linear():
    """The rejection and the PKCE check must ref their real causes, not seq-1."""
    trace = run(_injection(pkce=True))
    events = {e.seq: e for e in trace.events}

    # The code issuance refs the authorization request it answers.
    issue = next(e for e in trace.events if e.actor == "auth_server" and e.phase == "redirect")
    receive_req = next(
        e for e in trace.events if e.actor == "auth_server" and e.phase == "authorize"
        and e.summary.startswith("Authorization server receives")
    )
    assert issue.refs == [receive_req.seq]

    # The attacker's interception refs the code issuance (where it got the code).
    intercept = next(e for e in trace.events if e.actor == "attacker" and e.phase == "redirect")
    assert issue.seq in intercept.refs

    # The PKCE check refs the code issuance (challenge origin) and the exchange
    # request — a non-linear anchor, not just the immediately preceding event.
    pkce_check = next(e for e in trace.events if e.check and e.check.name == "pkce_verifier_match")
    assert issue.seq in pkce_check.refs
    assert pkce_check.refs != [pkce_check.seq - 1]

    # The attacker's rejection step refs the check that rejected it.
    rejection = next(
        e for e in trace.events if e.actor == "attacker" and e.outcome == "attack_blocked"
    )
    assert rejection.refs == [pkce_check.seq]


# --- compare / paired diff -------------------------------------------------


def test_compare_diverges_at_the_pkce_check():
    resp = run_compare(_injection(pkce=False), _injection(pkce=True))
    validate_compare_response(resp)
    assert resp.divergences, "expected a non-empty divergences list"
    first = resp.divergences[0]
    assert first.reason == "pkce_verifier_match"
    assert first.capability == "pkce"
    # The divergence seq is the variant's PKCE check seq.
    pkce_check = next(
        e for e in resp.variant.events if e.check and e.check.name == "pkce_verifier_match"
    )
    assert first.seq == pkce_check.seq
    # And the runs are genuinely different flows either side of it.
    assert resp.baseline.verdict.attacker_got_token is True
    assert resp.variant.verdict.attacker_got_token is False


def test_compare_prefix_is_structurally_identical_until_divergence():
    """The whole point of the gesture: identical steps until the one that differs."""
    from otv.engine.compare import _fingerprint

    resp = run_compare(_injection(pkce=False), _injection(pkce=True))
    div_seq = resp.divergences[0].seq
    b = {e.seq: e for e in resp.baseline.events}
    v = {e.seq: e for e in resp.variant.events}
    for seq in range(1, div_seq):
        assert _fingerprint(b[seq]) == _fingerprint(v[seq]), f"step {seq} should match"
    assert _fingerprint(b[div_seq]) != _fingerprint(v[div_seq])
