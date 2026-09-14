"""Phase 5 — client-credentials grant, client-authentication methods, and the
static-secret-leak attack (defeated by private_key_jwt).

These exercise the real protocol outcomes, not scripted verdicts: each client
authentication method is genuinely verified, a leaked static secret really lets
an attacker mint a token, and a captured private_key_jwt assertion really fails
verification on replay.
"""

import jwt
import pytest

from otv import crypto, registry
from otv.actors.environment import ISSUER, RESOURCE_AUDIENCE
from otv.contract import FeatureState, ScenarioConfig, validate, validate_compare_response
from otv.engine.compare import run_compare
from otv.engine.conductor import UnsupportedScenario, run

# The client-credentials principal's client_id. Imported lazily inside the tests
# (rather than at module scope) so importing this test file never registers the
# r5 runner ahead of the package's filename-ordered discovery in load_all().
SERVICE_CLIENT_ID = "demo-service-client"

METHODS = ("client_secret_basic", "client_secret_post", "private_key_jwt")

# The first-class check each method emits, and the request field it hinges on.
CHECK_FOR = {
    "client_secret_basic": "client_secret_auth",
    "client_secret_post": "client_secret_auth",
    "private_key_jwt": "private_key_jwt_auth",
}
HIGHLIGHT_FOR = {
    "client_secret_basic": "request.headers.Authorization",
    "client_secret_post": "request.body.client_secret",
    "private_key_jwt": "request.body.client_assertion",
}


def _cc(method, *, leak=False):
    return ScenarioConfig(
        grant="client_credentials",
        capabilities={"client_auth": FeatureState(active=True, params={"method": method})},
        attacks={"static_secret_leak": FeatureState(active=True)} if leak else {},
    )


def _token_from(trace):
    for e in trace.events:
        if e.http and isinstance(e.http.response.body, dict):
            if "access_token" in e.http.response.body:
                return e.http.response.body["access_token"]
    return None


# --- The grant: the client itself is the principal, no user ----------------


@pytest.mark.parametrize("method", METHODS)
def test_client_credentials_issues_a_client_principal_token(method):
    trace = run(_cc(method))
    validate(trace)
    v = trace.verdict
    # No user participates in this grant.
    assert v.user_got_token is False
    assert v.user_accessed_resource is False
    assert v.attacker_got_token is False
    assert all(e.actor != "attacker" for e in trace.events)

    token = _token_from(trace)
    assert token, f"{method}: no access token issued"
    claims = crypto.decode_claims_unverified(token)
    # The subject is the CLIENT, not a user.
    assert claims["sub"] == SERVICE_CLIENT_ID
    assert claims["client_id"] == SERVICE_CLIENT_ID


@pytest.mark.parametrize("method", METHODS)
def test_client_credentials_token_is_a_real_verifiable_jwt(method):
    token = _token_from(run(_cc(method)))
    # A real signature: verification must FAIL against the wrong key.
    wrong = crypto.SigningKey.generate()
    with pytest.raises(jwt.PyJWTError):
        crypto.verify_access_token(
            token, jwks=wrong.jwks(), issuer=ISSUER, audience=RESOURCE_AUDIENCE
        )
    claims = crypto.decode_claims_unverified(token)
    assert claims["iss"] == ISSUER and claims["aud"] == RESOURCE_AUDIENCE


# --- Each client-authentication method is really verified -------------------


@pytest.mark.parametrize("method", METHODS)
def test_each_client_auth_method_is_verified_with_its_check_and_highlight(method):
    trace = run(_cc(method))
    checks = {e.check.name: e.check for e in trace.events if e.check}
    name = CHECK_FOR[method]
    assert name in checks, f"{method}: expected a {name} check"
    assert checks[name].result == "PASS"
    # The decisive request field is highlighted with its dotted path.
    highlights = [h for e in trace.events if e.http for h in e.http.highlight]
    assert HIGHLIGHT_FOR[method] in highlights, f"{method}: missing highlight"


# --- The attack: static-secret leak wins; private_key_jwt defeats it --------


@pytest.mark.parametrize("method", ("client_secret_basic", "client_secret_post"))
def test_static_secret_leak_wins_with_a_shared_secret(method):
    trace = run(_cc(method, leak=True))
    validate(trace)
    v = trace.verdict
    assert v.attacker_got_token is True, f"{method}: leaked static secret should win"
    assert v.responsible_capability is None
    # The attacker really holds a signed, client-scoped token.
    token = _token_from(trace)
    claims = crypto.decode_claims_unverified(token)
    assert claims["sub"] == SERVICE_CLIENT_ID


def test_private_key_jwt_defeats_the_reuse():
    trace = run(_cc("private_key_jwt", leak=True))
    validate(trace)
    v = trace.verdict
    assert v.attacker_got_token is False
    # Attributed to client_auth, derived from the failing check in the trace.
    assert v.responsible_capability == "client_auth"
    block = next(e for e in trace.events if e.seq == v.blocked_at_seq)
    assert block.check is not None
    assert block.check.name == "private_key_jwt_auth"
    assert block.check.result == "FAIL"
    # No token was issued to the attacker anywhere in the trace.
    assert _token_from(trace) is None


def test_responsible_capability_is_derived_from_the_failing_check():
    from otv.engine.runners.support import CHECK_TO_CAPABILITY

    # The block attribution is not hard-coded: the failing check name maps back to
    # the owning capability via the registry-derived table.
    assert CHECK_TO_CAPABILITY["private_key_jwt_auth"] == "client_auth"
    assert CHECK_TO_CAPABILITY["client_secret_auth"] == "client_auth"
    trace = run(_cc("private_key_jwt", leak=True))
    block = next(e for e in trace.events if e.seq == trace.verdict.blocked_at_seq)
    assert CHECK_TO_CAPABILITY[block.check.name] == trace.verdict.responsible_capability


# --- The paired diff (flow-2 vs flow-3) -------------------------------------


def test_leak_compare_diverges_at_the_client_auth_check():
    resp = run_compare(_cc("client_secret_basic", leak=True), _cc("private_key_jwt", leak=True))
    validate_compare_response(resp.to_dict())
    # Baseline (static secret) lets the attacker win; variant (private_key_jwt)
    # blocks it — the whole point of the contrast.
    assert resp.baseline.verdict.attacker_got_token is True
    assert resp.variant.verdict.attacker_got_token is False
    assert resp.divergences, "expected a divergence"
    first = resp.divergences[0]
    # They stay the same flow until the client-authentication step decides it.
    assert first.reason == "private_key_jwt_auth"
    # And the divergence lands on a step whose check actually differs.
    b = {e.seq: e for e in resp.baseline.events}
    v = {e.seq: e for e in resp.variant.events}
    assert v[first.seq].check is not None and v[first.seq].check.result == "FAIL"
    assert b[first.seq].check is None or b[first.seq].check.result == "PASS"


# --- Catalog availability ---------------------------------------------------


def test_client_auth_capability_is_catalogued_and_available():
    item = registry.get("client_auth")
    assert item is not None and item.kind == "capability"
    assert item.phase == 5 and item.available is True
    assert item.check_names == ["client_secret_auth", "private_key_jwt_auth"]
    # The static-secret-leak attack is now runnable too.
    leak = registry.get("static_secret_leak")
    assert leak.available is True and leak.applies_to_grants == ["client_credentials"]
    # Guard the test's local copy of the principal id against the runner's.
    from otv.engine.runners import r5_client_credentials as r5

    assert SERVICE_CLIENT_ID == r5.SERVICE_CLIENT_ID


def test_static_secret_leak_needs_the_client_credentials_grant():
    # The attack has no runner under the authorization-code grant, so the
    # conductor refuses it rather than faking a result.
    with pytest.raises(UnsupportedScenario):
        run(
            ScenarioConfig(
                grant="authorization_code",
                attacks={"static_secret_leak": FeatureState(active=True)},
            )
        )
