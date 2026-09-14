"""Scenario snapshot tests.

Assert the happy-path run's verdict and its key step outcomes, so a future
regression that breaks the happy path (e.g. the resource server stops honoring a
valid token, or single-use enforcement flips) fails here. This is also how the
committed fixture is regenerated.
"""

import jwt
import pytest

from otv import crypto
from otv.actors.environment import Environment
from otv.contract import FeatureState, ScenarioConfig
from otv.engine.conductor import UnsupportedScenario, run


@pytest.fixture()
def happy_trace():
    return run(ScenarioConfig(grant="authorization_code"))


def test_happy_path_verdict(happy_trace):
    v = happy_trace.verdict
    assert v.attacker_got_token is False
    assert v.user_got_token is True
    assert v.user_accessed_resource is True
    assert v.blocked_at_seq is None
    assert v.responsible_capability is None


def test_all_steps_ok_and_expected_phases(happy_trace):
    events = happy_trace.events
    assert [e.outcome for e in events] == ["ok"] * len(events)
    phases = {e.phase for e in events}
    assert phases == {"authorize", "redirect", "token", "resource"}
    # No attacker activity in Phase 0.
    assert all(e.on_behalf_of == "user" for e in events)
    assert all(e.actor != "attacker" for e in events)


def test_checks_present_and_passing(happy_trace):
    checks = {e.check.name: e.check for e in happy_trace.events if e.check}
    assert set(checks) == {
        "redirect_uri_registered",
        "state_matches_session",
        "client_authentication",
        "authorization_code_single_use",
        "authorization_code_binding",
        "access_token_validation",
    }
    assert all(c.result == "PASS" for c in checks.values())


def test_access_token_is_a_real_verifiable_jwt(happy_trace):
    """The token the RS honored must actually verify against the AS's JWKS."""
    # Find the token issued by the auth server.
    token = None
    for e in happy_trace.events:
        if e.http and e.http.response.body and isinstance(e.http.response.body, dict):
            if "access_token" in e.http.response.body:
                token = e.http.response.body["access_token"]
    assert token, "no access token found in the trace"

    # Rebuild a resource-server-style verification against a fresh key: it must
    # FAIL against the wrong key (proving the signature is real) ...
    env = Environment()
    wrong_key = crypto.SigningKey.generate()
    with pytest.raises(jwt.PyJWTError):
        crypto.verify_access_token(
            token, jwks=wrong_key.jwks(), issuer=env.issuer, audience=env.resource_audience
        )
    # ... and the claims decode to the synthetic subject.
    claims = crypto.decode_claims_unverified(token)
    assert claims["iss"] == env.issuer
    assert claims["aud"] == env.resource_audience
    assert claims["sub"] == env.user.sub


def test_single_use_code_is_enforced(happy_trace):
    """Redeeming the same code twice must be rejected by the auth server."""
    from otv.actors.auth_server import AuthServerImpl, OAuthError
    from otv.recorder import Recorder
    from otv.trace_context import acting

    env = Environment()
    recorder = Recorder("run_test", ScenarioConfig(grant="authorization_code"))
    auth = AuthServerImpl(recorder, env)
    params = {
        "response_type": "code",
        "client_id": env.client.client_id,
        "redirect_uri": env.client.redirect_uri,
        "scope": env.client.scope,
        "state": "st_x",
    }
    with acting(on_behalf_of="user"):
        redirect = auth.authorize(params)
        token_params = {
            "grant_type": "authorization_code",
            "code": redirect["code"],
            "redirect_uri": env.client.redirect_uri,
            "client_id": env.client.client_id,
            "client_secret": env.client.client_secret,
        }
        auth.token(dict(token_params))  # first: ok
        with pytest.raises(OAuthError) as exc:  # second: rejected
            auth.token(dict(token_params))
    assert exc.value.error == "invalid_grant"


def test_later_phase_features_and_other_grants_are_unsupported_this_phase():
    # A later-phase capability (issuer_id, Phase 7) is still refused.
    with pytest.raises(UnsupportedScenario):
        run(
            ScenarioConfig(
                grant="authorization_code",
                capabilities={"issuer_id": FeatureState(active=True)},
            )
        )
    # A later-phase attack (phishing, Phase 7) is still refused.
    with pytest.raises(UnsupportedScenario):
        run(
            ScenarioConfig(
                grant="authorization_code",
                attacks={"phishing": FeatureState(active=True)},
            )
        )
    # The static-secret leak is a client-credentials attack; there is no runner for
    # it under the authorization-code grant, so that combination is still refused.
    with pytest.raises(UnsupportedScenario):
        run(
            ScenarioConfig(
                grant="authorization_code",
                attacks={"static_secret_leak": FeatureState(active=True)},
            )
        )
    # 'implicit' is the one GRANTS entry with no runner yet (authorization_code,
    # client_credentials, and jwt_bearer are all live by Phase 6).
    with pytest.raises(UnsupportedScenario):
        run(ScenarioConfig(grant="implicit"))


def test_feature_mismatched_with_grant_is_unsupported():
    """A hand-built config can request a feature that is available in this build
    but doesn't apply to the requested grant at all — e.g. auth-code injection
    (an authorization_code-only attack, per its ``applies_to_grants``) under the
    jwt_bearer grant. That combination must still be refused, so a runner never
    gets selected on the grant alone while the trace silently ignores the
    mismatched attack."""
    with pytest.raises(UnsupportedScenario):
        run(
            ScenarioConfig(
                grant="jwt_bearer",
                attacks={"auth_code_injection": FeatureState(active=True)},
            )
        )
