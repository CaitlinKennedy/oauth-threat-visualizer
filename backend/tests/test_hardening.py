"""Contract-hardening tests.

Covers the additive contract growth (actor_instance, plural responsible
capabilities, chain_verdict, the compare/divergence shape), the strengthened
token validation (typ/nbf), the resource server's rejection paths and
token-bound profile lookup, the auth server's endpoint checks, and the honest
`state` check on the client.
"""

import time

import jwt
import pytest

from otv import crypto
from otv.actors.auth_server import AuthServerImpl, OAuthError
from otv.actors.client import ClientImpl
from otv.actors.environment import Environment, SyntheticUser
from otv.actors.resource_server import ResourceServerImpl
from otv.contract import (
    Check,
    ChainBlock,
    ChainVerdict,
    CompareResponse,
    ContractError,
    Divergence,
    HttpExchange,
    HttpMessage,
    KnowledgeState,
    ScenarioConfig,
    SpecRef,
    StepEvent,
    Trace,
    Verdict,
    validate,
    validate_compare_response,
)
from otv.engine.conductor import run
from otv.recorder import Recorder
from otv.trace_context import acting


# --- helpers ---------------------------------------------------------------


def _happy_dict():
    return run(ScenarioConfig(grant="authorization_code")).to_dict()


def _make_rs(env: Environment):
    recorder = Recorder("run_test", ScenarioConfig(grant="authorization_code"))
    auth = AuthServerImpl(recorder, env)
    rs = ResourceServerImpl(recorder, env.resource_server_config(), auth)
    return recorder, auth, rs


def _token_for(auth: AuthServerImpl, env: Environment, *, sub: str, **overrides):
    kw = dict(
        issuer=env.issuer,
        subject=sub,
        audience=env.resource_audience,
        client_id=env.client.client_id,
        scope="profile email",
    )
    kw.update(overrides)
    return crypto.sign_access_token(auth.signing_key, **kw)


# --- A1: actor_instance + instance-qualified knowledge_delta ---------------


def test_actor_instance_and_instanced_knowledge_delta_validate():
    d = _happy_dict()
    d["events"][0]["actor_instance"] = "honest"
    d["events"][0]["knowledge_delta"]["auth_server#rogue"] = {"has": ["code"], "lacks": []}
    validate(d)  # additive: must not raise


def test_knowledge_delta_rejects_unknown_actor_even_with_instance():
    d = _happy_dict()
    d["events"][0]["knowledge_delta"]["wizard#rogue"] = {"has": [], "lacks": []}
    with pytest.raises(ContractError):
        validate(d)


def test_actor_instance_must_be_string():
    d = _happy_dict()
    d["events"][0]["actor_instance"] = 5
    with pytest.raises(ContractError):
        validate(d)


# --- A2: plural responsible capabilities + chain_verdict -------------------


def test_responsible_capabilities_plural_validates():
    d = _happy_dict()
    d["verdict"]["responsible_capabilities"] = ["pkce", "state"]
    validate(d)


def test_bad_responsible_capabilities_rejected():
    d = _happy_dict()
    d["verdict"]["responsible_capabilities"] = "pkce"
    with pytest.raises(ContractError):
        validate(d)


def test_chain_verdict_roundtrips_and_validates():
    trace = run(ScenarioConfig(grant="authorization_code"))
    trace.chain_id = "chain_1"
    trace.chain_verdict = ChainVerdict(
        attacker_got_token=False,
        responsible_capabilities=["pkce", "state"],
        blocked_at=ChainBlock(trace_id=trace.correlation_id, seq=9),
    )
    d = trace.to_dict()
    assert d["chain_verdict"]["blocked_at"]["seq"] == 9
    validate(d)


def test_invalid_chain_verdict_rejected():
    d = _happy_dict()
    d["chain_verdict"] = {"attacker_got_token": "nope"}
    with pytest.raises(ContractError):
        validate(d)


# --- A3: compare / divergence shape ----------------------------------------


def test_compare_response_shape_validates():
    base = run(ScenarioConfig(grant="authorization_code"))
    variant = run(ScenarioConfig(grant="authorization_code"))
    resp = CompareResponse(
        baseline=base,
        variant=variant,
        divergences=[Divergence(seq=9, reason="pkce_verifier_match", capability="pkce")],
    )
    d = resp.to_dict()
    assert d["mode"] == "compare"
    assert isinstance(d["divergences"], list)
    assert d["divergence"] == d["divergences"][0]  # convenience alias
    validate_compare_response(resp)
    validate_compare_response(d)


def test_compare_response_rejects_bad_divergence():
    base = run(ScenarioConfig(grant="authorization_code"))
    d = CompareResponse(baseline=base, variant=base).to_dict()
    d["divergences"] = [{"seq": "nope", "reason": "x", "capability": "y"}]
    with pytest.raises(ContractError):
        validate_compare_response(d)


def test_partial_outcome_is_valid():
    d = _happy_dict()
    d["events"][-1]["outcome"] = "partial"
    validate(d)


# --- A7: highlight must be pathed strings ----------------------------------


def test_highlight_entries_must_be_strings():
    d = _happy_dict()
    for e in d["events"]:
        if e.get("http"):
            e["http"]["highlight"] = [123]
            break
    with pytest.raises(ContractError):
        validate(d)


# --- B6: source/target actors validated ------------------------------------


def test_http_source_target_actor_must_be_known():
    d = _happy_dict()
    for e in d["events"]:
        if e.get("http"):
            e["http"]["source_actor"] = "wizard"
            break
    with pytest.raises(ContractError):
        validate(d)


# --- crypto: typ=at+jwt (RFC 9068) and nbf required ------------------------


def test_verify_rejects_non_access_token_typ():
    env = Environment()
    key = crypto.SigningKey.generate(kid="k1")
    now = int(time.time())
    claims = {
        "iss": env.issuer,
        "sub": env.user.sub,
        "aud": env.resource_audience,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
    }
    # A JWT signed by the same key but typed as an ID token, not an access token.
    id_token = jwt.encode(claims, key._private_pem, algorithm="RS256", headers={"kid": "k1", "typ": "JWT"})
    with pytest.raises(jwt.PyJWTError):
        crypto.verify_access_token(
            id_token, jwks=key.jwks(), issuer=env.issuer, audience=env.resource_audience
        )


def test_verify_accepts_media_type_form_of_typ():
    env = Environment()
    key = crypto.SigningKey.generate(kid="k1")
    now = int(time.time())
    claims = {
        "iss": env.issuer,
        "sub": env.user.sub,
        "aud": env.resource_audience,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
    }
    tok = jwt.encode(
        claims, key._private_pem, algorithm="RS256", headers={"kid": "k1", "typ": "application/at+jwt"}
    )
    claims_out = crypto.verify_access_token(
        tok, jwks=key.jwks(), issuer=env.issuer, audience=env.resource_audience
    )
    assert claims_out["sub"] == env.user.sub


def test_verify_requires_nbf():
    env = Environment()
    key = crypto.SigningKey.generate(kid="k1")
    now = int(time.time())
    claims = {  # deliberately no nbf
        "iss": env.issuer,
        "sub": env.user.sub,
        "aud": env.resource_audience,
        "iat": now,
        "exp": now + 300,
    }
    tok = jwt.encode(claims, key._private_pem, algorithm="RS256", headers={"kid": "k1", "typ": "at+jwt"})
    with pytest.raises(jwt.PyJWTError):
        crypto.verify_access_token(
            tok, jwks=key.jwks(), issuer=env.issuer, audience=env.resource_audience
        )


# --- RS: rejection paths (tampered / expired / wrong-aud) ------------------


@pytest.mark.parametrize("kind", ["tampered", "expired", "wrong_aud"])
def test_rs_rejects_bad_token(kind):
    env = Environment()
    recorder, auth, rs = _make_rs(env)
    if kind == "tampered":
        token = _token_for(auth, env, sub=env.user.sub)[:-4] + "AAAA"
    elif kind == "expired":
        token = _token_for(auth, env, sub=env.user.sub, ttl_seconds=-10)
    else:
        token = _token_for(auth, env, sub=env.user.sub, audience="https://evil.example")
    with acting(on_behalf_of="user"):
        result = rs.get_resource({"headers": {"Authorization": f"Bearer {token}"}})
    assert result["ok"] is False
    check_event = next(e for e in recorder.events if e.check and e.check.name == "access_token_validation")
    assert check_event.check.result == "FAIL"
    assert check_event.outcome == "blocked"
    assert check_event.http.response.status == 401


# --- ADD-5: RS binds the profile to the token's sub ------------------------


def test_rs_serves_the_profile_for_the_tokens_subject():
    victim = SyntheticUser(sub="user-victim", username="victim", display_name="Vic Tim", email="vic@x")
    attacker = SyntheticUser(
        sub="user-attacker", username="mallory", display_name="Mallory", email="mal@x"
    )
    env = Environment(user=victim, users=[victim, attacker])
    recorder, auth, rs = _make_rs(env)
    token = _token_for(auth, env, sub=attacker.sub)
    with acting(on_behalf_of="attacker"):
        result = rs.get_resource({"headers": {"Authorization": f"Bearer {token}"}})
    assert result["ok"] is True
    # The profile must be the attacker's own, NOT the ambient/first user's.
    assert result["resource"]["username"] == "mallory"


def test_rs_returns_not_found_for_unknown_subject():
    env = Environment()
    recorder, auth, rs = _make_rs(env)
    token = _token_for(auth, env, sub="user-nobody")
    with acting(on_behalf_of="user"):
        result = rs.get_resource({"headers": {"Authorization": f"Bearer {token}"}})
    assert result["ok"] is False
    miss = recorder.events[-1]
    assert miss.outcome == "blocked"
    assert miss.http.response.status == 404


# --- AS: token-endpoint mismatch behaviour ---------------------------------


def _authorize_and_get_code(auth: AuthServerImpl, env: Environment):
    params = {
        "response_type": "code",
        "client_id": env.client.client_id,
        "redirect_uri": env.client.redirect_uri,
        "scope": env.client.scope,
        "state": "st_x",
    }
    return auth.authorize(params)["code"]


def test_token_endpoint_rejects_wrong_client_secret():
    env = Environment()
    recorder = Recorder("run_test", ScenarioConfig(grant="authorization_code"))
    auth = AuthServerImpl(recorder, env)
    with acting(on_behalf_of="user"):
        code = _authorize_and_get_code(auth, env)
        with pytest.raises(OAuthError) as exc:
            auth.token(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": env.client.redirect_uri,
                    "client_id": env.client.client_id,
                    "client_secret": "WRONG",
                }
            )
    assert exc.value.error == "invalid_client"
    assert exc.value.status == 401
    auth_check = next(e for e in recorder.events if e.check and e.check.name == "client_authentication")
    assert auth_check.check.result == "FAIL"


def test_token_endpoint_rejects_redirect_uri_mismatch():
    env = Environment()
    recorder = Recorder("run_test", ScenarioConfig(grant="authorization_code"))
    auth = AuthServerImpl(recorder, env)
    with acting(on_behalf_of="user"):
        code = _authorize_and_get_code(auth, env)
        with pytest.raises(OAuthError) as exc:
            auth.token(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": "https://app.oauthlab.internal/somewhere-else",
                    "client_id": env.client.client_id,
                    "client_secret": env.client.client_secret,
                }
            )
    assert exc.value.error == "invalid_grant"
    binding = next(e for e in recorder.events if e.check and e.check.name == "authorization_code_binding")
    assert binding.check.result == "FAIL"


# --- ADD-3: client reports the state check honestly ------------------------


def test_client_state_mismatch_is_reported_as_failed_check():
    env = Environment()
    recorder = Recorder("run_test", ScenarioConfig(grant="authorization_code"))
    client = ClientImpl(recorder, env)
    with acting(on_behalf_of="user"):
        client.start_authorization()
        received = client.receive_redirect({"code": "ac_x", "state": "not-the-right-state"})
    assert received["state_ok"] is False
    ev = next(e for e in recorder.events if e.check and e.check.name == "state_matches_session")
    assert ev.check.result == "FAIL"
    assert ev.outcome == "blocked"
    assert "does NOT match" in ev.detail


def test_client_state_match_is_ok():
    env = Environment()
    recorder = Recorder("run_test", ScenarioConfig(grant="authorization_code"))
    client = ClientImpl(recorder, env)
    with acting(on_behalf_of="user"):
        started = client.start_authorization()
        received = client.receive_redirect(
            {"code": "ac_x", "state": started["params"]["state"]}
        )
    assert received["state_ok"] is True
    ev = next(e for e in recorder.events if e.check and e.check.name == "state_matches_session")
    assert ev.check.result == "PASS"
    assert ev.outcome == "ok"


# --- B2: the resource server is not handed AS/client secrets ---------------


def test_resource_server_config_excludes_client_secret_and_client_table():
    env = Environment()
    rs_config = env.resource_server_config()
    # Only role-appropriate facts are present; no client secret / registration table.
    assert not hasattr(rs_config, "client")
    assert "client_secret" not in vars(rs_config)
    assert set(rs_config.users_by_sub) == {env.user.sub}
