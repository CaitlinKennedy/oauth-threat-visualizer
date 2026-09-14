"""CSRF / cross-session code-injection runner (RFC 6749 §10.12).

The attacker logs in as *itself* and obtains a valid authorization code for the
victim's client, then delivers it into the victim's browser. What happens next is
decided by the ``state`` capability:

- **state off** — the victim's client does not enforce the returned ``state``, so
  it redeems the attacker's code and ends up bound to the attacker's account
  (login CSRF). The client reports the ``state`` mismatch honestly but proceeds.
- **state on** — the injected code arrives without the ``state`` the victim's
  client generated, so the client rejects the response *before* redemption; the
  block is attributed to ``state``, derived from the failing check.
"""

from __future__ import annotations

from typing import Optional

from ...actors.attacker import AttackerImpl
from ...actors.auth_server import AuthServer, AuthServerImpl
from ...actors.client import Client, ClientImpl
from ...actors.environment import Environment, SyntheticUser
from ...actors.resource_server import ResourceServer, ResourceServerImpl
from ...contract import ScenarioConfig, Trace, Verdict
from ...recorder import Recorder
from ...trace_context import acting
from . import Runner, register
from .support import CHECK_TO_CAPABILITY, event_at, new_run_id, state_active


def _matches(config: ScenarioConfig) -> bool:
    return "csrf_code_injection" in config.active_attacks()


def _attacker_user() -> SyntheticUser:
    return SyntheticUser(
        sub="user-mallory",
        username="mallory",
        display_name="Mallory Quill",
        email="mallory@oauthlab.internal",
    )


def _run(config: ScenarioConfig) -> Trace:
    recorder = Recorder(new_run_id(), config)
    victim = SyntheticUser()  # the default synthetic user (Avery)
    attacker_user = _attacker_user()
    # The RS must be able to serve the attacker's profile so the cross-session
    # binding is visible; the default user stays the victim.
    env = Environment(user=victim, users=[victim, attacker_user])
    enforce = state_active(config)

    # The victim's client is the confidential web client (no PKCE): with state as
    # the toggle under test, nothing else stands between the injected code and a
    # redemption — the legitimate client authenticates fine, because it IS the
    # legitimate client redeeming.
    client: Client = ClientImpl(recorder, env, enforce_state=enforce)
    auth_server: AuthServer = AuthServerImpl(recorder, env)
    resource_server: ResourceServer = ResourceServerImpl(
        recorder, env.resource_server_config(), auth_server
    )
    attacker = AttackerImpl(recorder, env, active=True)

    victim_client = env.client

    # 1) The victim's client begins its own login (generating a session 'state').
    with acting(on_behalf_of="user"):
        client.start_authorization()

    # 2) The attacker, authenticated as itself, obtains a valid code for the
    #    victim's client (bound to the attacker's account), then injects it.
    attacker_authz = {
        "response_type": "code",
        "client_id": victim_client.client_id,
        "redirect_uri": victim_client.redirect_uri,
        "scope": victim_client.scope,
        # No 'state': the attacker cannot know the victim client's session value.
    }
    with acting(on_behalf_of="attacker", source_actor="attacker", as_user=attacker_user):
        atk_redirect = auth_server.authorize(attacker_authz)
    with acting(on_behalf_of="attacker", source_actor="attacker"):
        attacker.stage_csrf_injection(
            atk_redirect["code"], obtained_from_seq=atk_redirect["issue_seq"]
        )

    # 3) The victim's client receives the injected code (no matching 'state').
    injected = {"code": atk_redirect["code"], "state": atk_redirect.get("state")}
    with acting(on_behalf_of="user"):
        received = client.receive_redirect(injected)
        if received["blocked"]:
            # state ON: rejected before redemption.
            return recorder.seal(_blocked_verdict(recorder, received["seq"]))
        # state OFF (honest report): the client proceeds to redeem the injected code.
        client.exchange_code(received["code"], auth_server=auth_server)
        result = client.access_resource(resource_server=resource_server)

    # 4) The binding is achieved: the victim's client now holds a token for the
    #    attacker's account.
    with acting(on_behalf_of="attacker", source_actor="attacker"):
        attacker.note_cross_session_binding(at_seq=result["seq"])

    return recorder.seal(_success_verdict(bound_username=attacker_user.username))


def _blocked_verdict(recorder: Recorder, at_seq: Optional[int]) -> Verdict:
    blocking = event_at(recorder, at_seq)
    responsible: Optional[str] = None
    if blocking is not None and blocking.check is not None:
        responsible = CHECK_TO_CAPABILITY.get(blocking.check.name)
    caps = [responsible] if responsible else []
    return Verdict(
        attacker_got_token=False,
        user_got_token=False,
        user_accessed_resource=False,
        one_line=(
            "Attacker obtained an access token: NO — the 'state' check blocked the "
            "cross-session code injection. The injected code arrived without the "
            "'state' the victim's client generated, so the client rejected the "
            "response before redeeming it. User obtained an access token: NO — the "
            "victim's own login was not completed."
        ),
        blocked_at_seq=at_seq,
        responsible_capability=responsible,
        responsible_capabilities=caps,
    )


def _success_verdict(*, bound_username: str) -> Verdict:
    return Verdict(
        # The attacker did not steal the victim's token; the harm is the reverse —
        # the victim's client is bound to the ATTACKER's account (login CSRF).
        attacker_got_token=False,
        user_got_token=True,
        user_accessed_resource=True,
        one_line=(
            "Cross-session binding SUCCEEDED — with no 'state' check the victim's "
            "client redeemed the attacker's code and is now bound to the attacker's "
            f"account ('{bound_username}'): a login-CSRF. Turning on 'state' blocks it "
            "at the redirect. Attacker obtained the victim's token: NO — the harm is "
            "the reverse binding, not a stolen token."
        ),
        blocked_at_seq=None,
        responsible_capability=None,
        responsible_capabilities=[],
    )


register(Runner(id="csrf_code_injection", matches=_matches, run=_run, order=40))
