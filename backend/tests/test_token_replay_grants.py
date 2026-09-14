"""Access-token replay under the back-channel grants.

Client credentials and JWT bearer have no authorization request or redirect, but
both still issue an access token that can be stolen and replayed at the resource
server. The same single toggle decides it: a plain bearer token is replayed
successfully, a DPoP-bound one fails the resource server's key-binding check.
"""

import pytest

from otv.contract import FeatureState, ScenarioConfig
from otv.engine.compare import run_compare
from otv.engine.conductor import run

GRANTS = ["client_credentials", "jwt_bearer"]


def _cfg(grant: str, dpop: bool) -> ScenarioConfig:
    return ScenarioConfig(
        grant=grant,
        capabilities={"dpop": FeatureState(active=dpop)},
        attacks={"token_replay": FeatureState(active=True)},
    )


@pytest.mark.parametrize("dpop", [False, True])
@pytest.mark.parametrize("grant", GRANTS)
def test_trace_has_no_front_channel_steps(grant, dpop):
    trace = run(_cfg(grant, dpop))
    assert {e.phase for e in trace.events} <= {"token", "resource"}


@pytest.mark.parametrize("dpop", [False, True])
@pytest.mark.parametrize("grant", GRANTS)
def test_honest_client_reads_its_resource_before_the_theft(grant, dpop):
    trace = run(_cfg(grant, dpop))
    served = [
        e
        for e in trace.events
        if e.actor == "resource_server"
        and e.summary == "Resource server returns the protected resource."
        and e.on_behalf_of != "attacker"
    ]
    assert served


@pytest.mark.parametrize("grant", GRANTS)
def test_stolen_bearer_token_is_replayed(grant):
    trace = run(_cfg(grant, dpop=False))
    assert trace.verdict.attacker_got_token is True
    assert trace.verdict.responsible_capability is None
    assert not any(e.check and e.check.name == "dpop_binding" for e in trace.events)


@pytest.mark.parametrize("grant", GRANTS)
def test_dpop_bound_token_replay_is_blocked_at_the_resource_server(grant):
    trace = run(_cfg(grant, dpop=True))
    v = trace.verdict
    assert v.attacker_got_token is False
    assert v.responsible_capabilities == ["dpop"]
    blocked = next(e for e in trace.events if e.seq == v.blocked_at_seq)
    assert blocked.actor == "resource_server"
    assert blocked.on_behalf_of == "attacker"
    assert blocked.check.name == "dpop_binding"
    assert blocked.check.result == "FAIL"
    assert any(
        e.check and e.check.name == "dpop_binding" and e.check.result == "PASS"
        for e in trace.events
    ), "the honest holder's proof must satisfy dpop_binding"


@pytest.mark.parametrize("grant", GRANTS)
def test_compare_diverges_at_the_dpop_binding(grant):
    resp = run_compare(_cfg(grant, dpop=False), _cfg(grant, dpop=True))
    assert resp.divergences[0].capability == "dpop"
    assert resp.baseline.verdict.attacker_got_token is True
    assert resp.variant.verdict.attacker_got_token is False
