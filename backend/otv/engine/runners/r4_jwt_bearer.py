"""JWT bearer grant runners (RFC 7523) — the Phase 4 orchestrations.

Two runners for the ``jwt_bearer`` grant:

- **jwt_bearer_happy** — the clean grant: a client presents a real signed
  assertion (``sub`` = the user) directly to the token endpoint and gets a
  user-scoped token, with no browser, redirect, or consent. Because there is no
  front channel, the front-channel attacks have nothing to target — the picker
  scopes them to the authorization-code grant (``applies_to_grants``), so they are
  simply not offered here.

- **assertion_replay** — the residual attack once the front channel is gone: the
  attacker captures a still-valid assertion and replays it. With
  ``assertion_replay_protection`` on, the genuine one-time-``jti`` check rejects
  the reuse (and the verdict's responsible capability is derived from that failing
  check via the registry); with it off, the server honors the replay and the
  attacker gets a user-scoped token. This gives the clean flow-2↔3 paired diff.
"""

from __future__ import annotations

from typing import Optional

from ...actors.environment import Environment
from ...actors.jwt_bearer import (
    JwtBearerAttacker,
    JwtBearerAuthServer,
    JwtBearerClient,
)
from ...actors.resource_server import ResourceServer, ResourceServerImpl
from ... import crypto
from ...contract import ScenarioConfig, Trace, Verdict
from ...recorder import Recorder
from ...trace_context import acting
from . import Runner, register
from .support import CHECK_TO_CAPABILITY, event_at, new_run_id


def _replay_protection_active(config: ScenarioConfig) -> bool:
    st = config.capabilities.get("assertion_replay_protection")
    return bool(st and st.active)


def _build(config: ScenarioConfig):
    """Construct the jwt-bearer actors wired to one shared assertion key."""
    recorder = Recorder(new_run_id(), config)
    env = Environment()
    # One real signing key: the client mints assertions with the private half; the
    # AS trusts the public half (registered as the issuer's JWKS).
    client_key = crypto.SigningKey.generate(kid="issuer-2026-09")
    client = JwtBearerClient(recorder, env, signing_key=client_key)
    auth_server = JwtBearerAuthServer(
        recorder,
        env,
        trusted_issuers={client.issuer_id: client_key.jwks()},
        enforce_replay_protection=_replay_protection_active(config),
    )
    resource_server: ResourceServer = ResourceServerImpl(
        recorder, env.resource_server_config(), auth_server
    )
    return recorder, env, client, auth_server, resource_server


# --- Happy path -------------------------------------------------------------


def _happy_matches(config: ScenarioConfig) -> bool:
    return config.grant == "jwt_bearer" and not config.active_attacks()


def _happy_run(config: ScenarioConfig) -> Trace:
    recorder, _env, client, auth_server, resource_server = _build(config)

    with acting(on_behalf_of="user"):
        client.mint_assertion()
        exchanged = client.present_assertion(auth_server=auth_server)
        result = client.access_resource(resource_server=resource_server)

    token_response = exchanged["token_response"]
    verdict = Verdict(
        attacker_got_token=False,
        user_got_token=bool(token_response.get("access_token")),
        user_accessed_resource=bool(result["ok"]),
        one_line=(
            "User obtained an access token: YES — the client exchanged a signed JWT "
            "assertion directly for a user-scoped token, with no browser, redirect, or "
            "consent. Attacker obtained an access token: NO — no attack was attempted, "
            "and with no front channel the front-channel attacks do not apply here."
        ),
        blocked_at_seq=None,
        responsible_capability=None,
    )
    return recorder.seal(verdict)


# --- Assertion replay -------------------------------------------------------


def _replay_matches(config: ScenarioConfig) -> bool:
    return config.grant == "jwt_bearer" and "assertion_replay" in config.active_attacks()


def _replay_run(config: ScenarioConfig) -> Trace:
    recorder, env, client, auth_server, resource_server = _build(config)
    attacker = JwtBearerAttacker(recorder, env)

    # 1) The honest client completes a genuine jwt-bearer exchange, spending its
    #    assertion's jti.
    with acting(on_behalf_of="user"):
        minted = client.mint_assertion()
        honest = client.present_assertion(auth_server=auth_server)
        honest_result = client.access_resource(resource_server=resource_server)

    # 2) The attacker captures a copy of the same assertion and replays it.
    with acting(on_behalf_of="attacker", source_actor="attacker"):
        attacker.capture_assertion(minted["assertion"], obtained_from_seq=minted["seq"])
    outcome = attacker.replay_assertion(auth_server=auth_server)
    if outcome["got_token"]:
        # Impact: the replayed-flow token reads the user's protected profile.
        attacker.access_resource(resource_server=resource_server)

    user_got_token = bool(honest["token_response"].get("access_token"))
    user_accessed_resource = bool(honest_result["ok"])
    verdict = _replay_verdict(
        recorder,
        attacker_got_token=bool(outcome["got_token"]),
        at_seq=outcome.get("at_seq"),
        user_got_token=user_got_token,
        user_accessed_resource=user_accessed_resource,
    )
    return recorder.seal(verdict)


def _replay_verdict(
    recorder: Recorder,
    *,
    attacker_got_token: bool,
    at_seq: Optional[int],
    user_got_token: bool,
    user_accessed_resource: bool,
) -> Verdict:
    if attacker_got_token:
        return Verdict(
            attacker_got_token=True,
            user_got_token=user_got_token,
            user_accessed_resource=user_accessed_resource,
            one_line=(
                "Attacker obtained an access token: YES — with no replay protection a "
                "captured, still-valid assertion could be replayed at the token "
                "endpoint for a user-scoped token. User obtained an access token: YES — "
                "the honest exchange completed first. Turning on assertion replay "
                "protection (one-time jti) blocks the replay."
            ),
            blocked_at_seq=None,
            responsible_capability=None,
            responsible_capabilities=[],
        )

    # The block is derived from the failing check in the emitted trace, mapped to
    # its owning capability via the registry (never hard-coded).
    blocking = event_at(recorder, at_seq)
    responsible: Optional[str] = None
    if blocking is not None and blocking.check is not None:
        responsible = CHECK_TO_CAPABILITY.get(blocking.check.name)
    responsible_caps = [responsible] if responsible else []
    return Verdict(
        attacker_got_token=False,
        user_got_token=user_got_token,
        user_accessed_resource=user_accessed_resource,
        one_line=(
            "Attacker obtained an access token: NO — the replayed assertion was "
            "rejected. Its signature and claims still verify, but its jti was already "
            "redeemed and one-time use is enforced (with a short exp and aud binding "
            "behind it), and the attacker cannot mint a fresh assertion without the "
            "signing key. User obtained an access token: YES — the honest exchange "
            "completed first."
        ),
        blocked_at_seq=at_seq,
        responsible_capability=responsible,
        responsible_capabilities=responsible_caps,
    )


register(Runner(id="jwt_bearer_happy", matches=_happy_matches, run=_happy_run))
register(Runner(id="assertion_replay", matches=_replay_matches, run=_replay_run))
