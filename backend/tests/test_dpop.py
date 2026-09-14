"""DPoP (RFC 9449) + token-replay tests.

Assert the decisive single-toggle behaviour: a stolen bearer token is replayed
successfully, but the *same* theft fails at the resource server once the token is
sender-constrained with DPoP. The block is produced by real crypto (a proof the
attacker cannot sign with the client's key), and the responsible capability is
derived from the failing check, not hard-coded.
"""

import jwt
import pytest

from otv import crypto, registry
from otv.contract import FeatureState, ScenarioConfig
from otv.engine.compare import run_compare
from otv.engine.conductor import run


def _cfg(dpop: bool) -> ScenarioConfig:
    return ScenarioConfig(
        grant="authorization_code",
        capabilities={"dpop": FeatureState(active=dpop)},
        attacks={"token_replay": FeatureState(active=True)},
    )


def _issued_token(trace):
    for e in trace.events:
        body = e.http.response.body if (e.http and e.http.response) else None
        if isinstance(body, dict) and "access_token" in body:
            return body["access_token"]
    return None


# --- crypto: thumbprint + proof round-trip ---------------------------------


def test_jwk_thumbprint_is_rfc7638_stable_and_key_specific():
    k1 = crypto.DpopKey.generate()
    # The thumbprint is a pure function of the public key.
    assert k1.thumbprint() == crypto.jwk_thumbprint(k1.public_jwk())
    assert len(k1.thumbprint()) == 43  # base64url of a 32-byte SHA-256, unpadded
    # Distinct keys have distinct thumbprints.
    assert k1.thumbprint() != crypto.DpopKey.generate().thumbprint()


def test_dpop_proof_verifies_only_for_matching_method_uri():
    key = crypto.DpopKey.generate()
    proof = crypto.create_dpop_proof(key, htm="GET", htu="https://api/x")
    bound = crypto.verify_dpop_proof(proof, htm="GET", htu="https://api/x")
    assert bound["jkt"] == key.thumbprint()
    # An htu/htm mismatch is rejected.
    with pytest.raises(jwt.PyJWTError):
        crypto.verify_dpop_proof(proof, htm="POST", htu="https://api/x")
    with pytest.raises(jwt.PyJWTError):
        crypto.verify_dpop_proof(proof, htm="GET", htu="https://api/other")


# --- token binding (cnf.jkt) -----------------------------------------------


def test_dpop_token_carries_cnf_jkt_matching_the_clients_key():
    trace = run(_cfg(dpop=True))
    token = _issued_token(trace)
    claims = crypto.decode_claims_unverified(token)
    jkt = claims.get("cnf", {}).get("jkt")
    assert jkt, "a DPoP run must bind the token via cnf.jkt"
    # The RS dpop_binding check's expected value is exactly that thumbprint.
    binding = next(
        e for e in trace.events if e.check and e.check.name == "dpop_binding"
    )
    assert binding.check.expected == jkt


def test_bearer_token_has_no_cnf_and_takes_the_bearer_path():
    trace = run(_cfg(dpop=False))
    token = _issued_token(trace)
    assert "cnf" not in crypto.decode_claims_unverified(token)
    # No DPoP binding check is ever emitted when DPoP is off.
    assert all(
        not (e.check and e.check.name == "dpop_binding") for e in trace.events
    )


# --- the decisive single-toggle aha ----------------------------------------


def test_honest_dpop_client_is_served_by_the_resource_server():
    """A DPoP-bound token verifies with the matching proof (honest lane)."""
    trace = run(_cfg(dpop=True))
    assert trace.verdict.user_got_token is True
    assert trace.verdict.user_accessed_resource is True
    binding_passes = [
        e for e in trace.events
        if e.check and e.check.name == "dpop_binding" and e.check.result == "PASS"
    ]
    assert binding_passes, "the honest holder's proof must satisfy dpop_binding"


def test_stolen_bearer_token_works_but_dpop_bound_token_is_blocked():
    bearer = run(_cfg(dpop=False))
    dpop = run(_cfg(dpop=True))

    # Bearer: the stolen token is replayed successfully.
    assert bearer.verdict.attacker_got_token is True
    assert bearer.verdict.responsible_capability is None

    # DPoP: the SAME theft fails at the resource server.
    assert dpop.verdict.attacker_got_token is False
    assert dpop.verdict.responsible_capability == "dpop"
    assert dpop.verdict.responsible_capabilities == ["dpop"]

    # The block is a real FAIL of the RS dpop_binding check, attributed to the
    # attacker lane, and the verdict points at exactly that step.
    blocked = next(e for e in dpop.events if e.seq == dpop.verdict.blocked_at_seq)
    assert blocked.actor == "resource_server"
    assert blocked.on_behalf_of == "attacker"
    assert blocked.check.name == "dpop_binding"
    assert blocked.check.result == "FAIL"


def test_responsible_capability_is_derived_from_the_failing_check():
    """The verdict's blocker is read from CHECK_TO_CAPABILITY, not hard-coded."""
    from otv.engine.runners.support import CHECK_TO_CAPABILITY

    assert CHECK_TO_CAPABILITY["dpop_binding"] == "dpop"
    dpop = run(_cfg(dpop=True))
    blocked = next(e for e in dpop.events if e.seq == dpop.verdict.blocked_at_seq)
    assert dpop.verdict.responsible_capability == CHECK_TO_CAPABILITY[blocked.check.name]


def test_attacker_knowledge_is_honest_has_token_lacks_key():
    dpop = run(_cfg(dpop=True))
    theft = next(
        e for e in dpop.events
        if e.actor == "attacker" and "attacker" in e.knowledge_delta
        and "access_token" in e.knowledge_delta["attacker"].has
    )
    kd = theft.knowledge_delta["attacker"]
    assert "access_token" in kd.has
    assert "dpop_private_key" in kd.lacks


# --- compare: divergence at the RS binding check ----------------------------


def test_compare_diverges_at_the_resource_server_dpop_check():
    resp = run_compare(_cfg(dpop=False), _cfg(dpop=True))
    assert resp.divergences, "expected a divergence"
    first = resp.divergences[0]
    assert first.reason == "dpop_binding"
    assert first.capability == "dpop"
    # The diverging step is at the resource server.
    variant_step = next(e for e in resp.variant.events if e.seq == first.seq)
    assert variant_step.actor == "resource_server"
    assert resp.baseline.verdict.attacker_got_token is True
    assert resp.variant.verdict.attacker_got_token is False


# --- catalog ----------------------------------------------------------------


def test_dpop_and_token_replay_are_catalogued():
    by_id = {i.id: i for i in [*registry.CAPABILITIES, *registry.ATTACKS]}
    assert by_id["dpop"].kind == "capability"
    assert by_id["token_replay"].kind == "attack"
    assert by_id["dpop"].check_names == ["dpop_binding"]
