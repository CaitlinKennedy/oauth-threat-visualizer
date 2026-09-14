"""JWT bearer grant actors (RFC 7523 §2.1).

The JWT authorization grant exchanges a signed **assertion** directly for a token:
a trusted issuer signs an assertion whose ``sub`` is the user, the client presents
it to the token endpoint over the back channel, and a user-scoped access token
comes back — **no browser, no redirect, no consent**. Because there is no front
channel, the front-channel attacks (code injection/interception, redirect CSRF,
mix-up) have nothing to target here.

The counter-lesson is honest: the trust relocates onto the signing key + the
assertion, and the residual attack is **assertion replay**. This module keeps
every security-relevant step real:

- ``JwtBearerClient`` holds a real RSA signing key and mints a genuinely signed
  assertion (``iss`` = the client, the trusted issuer; ``sub`` = the user;
  ``aud`` = the token endpoint; short ``exp`` + fresh ``jti``).
- ``JwtBearerAuthServer`` is a real authorization server (it subclasses the base
  ``AuthServerImpl``, so it reuses the same signing key + JWKS the resource
  server already trusts) whose ``token_jwt_bearer`` endpoint verifies the
  assertion's signature against the issuer's JWKS and its ``iss``/``sub``/``aud``/
  ``exp`` (RFC 7523 §3), tracks each ``jti`` for one-time use, and signs a real
  RS256 access token.
- ``JwtBearerAttacker`` captures a valid assertion and replays it against the real
  endpoint. Whether that wins is decided by the protocol: with replay protection
  the genuine ``assertion_jti_single_use`` check rejects the reused ``jti``;
  without it the server observes the reuse but does not act on it.

The actor pieces live together in one module (mirroring the catalog/runner
plugin-seam convention) so the grant is a self-contained drop; they reuse the
shared ``crypto``, ``recorder``, and trace-context seams like every other actor.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .. import crypto, trace_context
from ..contract import Check, HttpExchange, HttpMessage, KnowledgeState, SpecRef
from ..recorder import Recorder
from .auth_server import AuthServerImpl, OAuthError
from .environment import Environment, RegisteredClient
from .resource_server import ResourceServer

# The grant type identifier (RFC 7523 §2.1).
JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class JwtBearerClient:
    """A client that authenticates a user by presenting a signed JWT assertion.

    The client is also the trusted assertion **issuer** here (a legitimate RFC
    7523 configuration: a trusted service vouches for its own users). It holds a
    real signing key whose public JWK the authorization server trusts, mints a
    signed assertion for the user, and exchanges it for a token over the back
    channel — no authorization request, redirect, or consent screen anywhere.
    """

    def __init__(
        self,
        recorder: Recorder,
        env: Environment,
        *,
        signing_key: crypto.SigningKey,
        registered_client: Optional[RegisteredClient] = None,
        assertion_ttl_seconds: int = 60,
        dpop: bool = False,
    ):
        self.recorder = recorder
        self.env = env
        self.registered = registered_client or env.client
        # DPoP (RFC 9449): when active, the exchange carries a proof so the AS
        # binds the token to this key (cnf.jkt), and every resource call proves
        # possession of it. Independent of the assertion signing key.
        self.dpop_key: Optional[crypto.DpopKey] = crypto.DpopKey.generate() if dpop else None
        # The client-as-issuer signing key. Only the public half is registered with
        # the AS; the private half never leaves the client, which is exactly why an
        # attacker who captures an assertion still cannot mint a fresh one.
        self.signing_key = signing_key
        self.assertion_ttl_seconds = assertion_ttl_seconds
        self._assertion: Optional[str] = None
        self._access_token: Optional[str] = None
        self._mint_seq: Optional[int] = None

    @property
    def issuer_id(self) -> str:
        """The assertion issuer identity (``iss``) — the client's own id."""
        return self.registered.client_id

    def mint_assertion(self) -> Dict[str, Any]:
        """Mint and sign a fresh JWT bearer assertion for the user.

        Returns ``{"assertion": <jwt>, "seq": <event seq>}``. The assertion binds
        the user (``sub``) to the token endpoint (``aud``) for a short window, and
        carries a fresh ``jti`` so the server can enforce one-time use.
        """
        user = self.env.user
        assertion = crypto.sign_assertion(
            self.signing_key,
            issuer=self.issuer_id,
            subject=user.sub,
            audience=self.env.token_url,
            ttl_seconds=self.assertion_ttl_seconds,
        )
        self._assertion = assertion
        claims = crypto.decode_claims_unverified(assertion)
        seq = self.recorder.emit(
            actor="client",
            phase="token",
            summary="Client mints and signs a JWT bearer assertion.",
            detail=(
                "There is no authorization request, redirect, or consent screen. The "
                "client (a trusted issuer for its users) signs a short-lived assertion "
                "with its own private key: 'iss' identifies the issuer, 'sub' is the "
                "user the token will be scoped to, 'aud' is the token endpoint, and a "
                "fresh 'jti' plus a short 'exp' make it one-time and time-boxed. Only "
                "the assertion's public key is registered with the authorization "
                "server; the private key never leaves the client."
            ),
            outcome="ok",
            http=HttpExchange(
                request=HttpMessage(method="POST", url=f"{self.issuer_id}/mint-assertion"),
                response=HttpMessage(
                    status=200,
                    body={
                        "iss": claims.get("iss"),
                        "sub": claims.get("sub"),
                        "aud": claims.get("aud"),
                        "exp": claims.get("exp"),
                        "jti": claims.get("jti"),
                    },
                ),
                highlight=["response.body.sub", "response.body.aud", "response.body.jti"],
                source_actor="client",
                target_actor="client",
            ),
            knowledge_delta={
                "client": KnowledgeState(has=["assertion_signing_key", "jwt_assertion"]),
            },
            spec_refs=[SpecRef(rfc="RFC 7523", section="§3")],
        )
        self._mint_seq = seq
        return {"assertion": assertion, "seq": seq}

    def present_assertion(self, *, auth_server: "JwtBearerAuthServer") -> Dict[str, Any]:
        """Exchange the assertion for an access token at the token endpoint.

        Drives the real ``token_jwt_bearer`` endpoint (which emits its own
        receive/verify/jti/issue steps), then records the client storing the token.
        Returns ``{"token_response": {...}, "seq": <event seq>}``.
        """
        assert self._assertion is not None, "present_assertion called before mint_assertion"
        token_request = {
            "grant_type": JWT_BEARER_GRANT_TYPE,
            "assertion": self._assertion,
        }
        if self.dpop_key is not None:
            token_request["dpop"] = crypto.create_dpop_proof(
                self.dpop_key, htm="POST", htu=self.env.token_url
            )
        token_response = auth_server.token_jwt_bearer(token_request)
        self._access_token = token_response["access_token"]
        seq = self.recorder.emit(
            actor="client",
            phase="token",
            summary="Client receives and stores the access token.",
            detail=(
                "The assertion verified and the token endpoint returned a signed, "
                "audience-scoped access token for the user — obtained without any "
                "front-channel interaction at all."
            ),
            outcome="ok",
            knowledge_delta={"client": KnowledgeState(has=["access_token"])},
            spec_refs=[SpecRef(rfc="RFC 7523", section="§2.1")],
        )
        return {"token_response": token_response, "seq": seq}

    def access_resource(self, *, resource_server: ResourceServer) -> Dict[str, Any]:
        """Call the protected resource with the stored access token."""
        assert self._access_token is not None, "access_resource before a token was obtained"
        if self.dpop_key is not None:
            headers = {
                "Authorization": f"DPoP {self._access_token}",
                "DPoP": crypto.create_dpop_proof(
                    self.dpop_key, htm="GET", htu=self.env.resource_url
                ),
            }
        else:
            headers = {"Authorization": f"Bearer {self._access_token}"}
        return resource_server.get_resource({"url": self.env.resource_url, "headers": headers})


class JwtBearerAuthServer(AuthServerImpl):
    """An authorization server that also implements the JWT bearer grant.

    Subclasses the base ``AuthServerImpl`` so it is a real AS: it reuses the
    same RS256 signing key and JWKS the resource server already trusts (inherited
    ``jwks()``), and simply adds the ``token_jwt_bearer`` endpoint. It holds the
    trusted assertion issuers' public keys and a seen-``jti`` store for one-time
    use enforcement.
    """

    def __init__(
        self,
        recorder: Recorder,
        env: Environment,
        *,
        trusted_issuers: Dict[str, Dict[str, Any]],
        enforce_replay_protection: bool = False,
    ):
        super().__init__(recorder, env)
        # iss -> the issuer's JWKS (public keys the AS trusts for assertions).
        self._trusted_issuers: Dict[str, Dict[str, Any]] = dict(trusted_issuers)
        self._enforce_replay_protection = enforce_replay_protection
        # jti values already redeemed (one-time-use store). Always maintained; the
        # capability toggle only decides whether a repeat is *rejected*.
        self._seen_jti: set[str] = set()

    def token_jwt_bearer(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Redeem a JWT bearer assertion for a signed access token (RFC 7523 §2.1).

        Verifies the assertion's signature against the issuer's registered JWKS and
        its ``iss``/``sub``/``aud``/``exp`` (RFC 7523 §3), enforces one-time ``jti``
        use when replay protection is active, and signs a real RS256 access token
        scoped to the assertion's subject. Each check is a first-class ``check``
        event (emitted on PASS too, so the paired diff can highlight it).
        """
        grant_type = request.get("grant_type")
        assertion = request.get("assertion")
        peer = trace_context.current_source_actor() or "client"

        receive_seq = self.recorder.emit(
            actor="auth_server",
            phase="token",
            summary="Token endpoint receives the JWT bearer assertion.",
            detail=(
                "The caller presents grant_type=urn:ietf:params:oauth:grant-type:"
                "jwt-bearer with a signed assertion, directly over the back channel. "
                "The server will verify the assertion before issuing anything."
            ),
            outcome="ok",
            http=HttpExchange(
                request=HttpMessage(
                    method="POST",
                    url=self.env.token_url,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        **({"DPoP": "<dpop_proof>"} if request.get("dpop") else {}),
                    },
                    body={"grant_type": grant_type, "assertion": "<signed_jwt_assertion>"},
                ),
                response=HttpMessage(status=200, body={"processing": True}),
                highlight=["request.body.grant_type", "request.body.assertion"],
                source_actor=peer,
                target_actor="auth_server",
            ),
            spec_refs=[SpecRef(rfc="RFC 7523", section="§2.1")],
        )

        if grant_type != JWT_BEARER_GRANT_TYPE:
            raise OAuthError("unsupported_grant_type", f"grant_type={grant_type!r}")

        # Verify the assertion: real signature check against the issuer's JWKS plus
        # iss / sub / aud=token endpoint / exp (RFC 7523 §3). The unverified 'iss'
        # only selects which trusted issuer's keys to check against; the signature
        # is what actually binds it.
        unverified = crypto.decode_claims_unverified(assertion) if assertion else {}
        iss = unverified.get("iss")
        issuer_jwks = self._trusted_issuers.get(iss) if iss is not None else None
        valid = True
        failure: Optional[str] = None
        claims: Dict[str, Any] = {}
        try:
            import jwt as _jwt  # local alias; crypto raises jwt.PyJWTError subclasses

            if issuer_jwks is None:
                raise _jwt.InvalidIssuerError(f"untrusted assertion issuer {iss!r}")
            claims = crypto.verify_assertion(
                assertion,
                jwks=issuer_jwks,
                issuer=iss,
                audience=self.env.token_url,
            )
        except Exception as exc:  # jwt.PyJWTError subclasses (signature/exp/aud/iss)
            valid = False
            failure = type(exc).__name__

        verify_seq = self.recorder.emit(
            actor="auth_server",
            phase="token",
            summary="Token endpoint verifies the assertion signature and claims.",
            detail=(
                "The server recomputes the JWS signature against the issuer's "
                "published key and checks that 'iss' is a trusted issuer, 'aud' is "
                "this token endpoint, and the assertion is within its 'exp' window. "
                "Only an assertion the issuer actually signed, for this endpoint, and "
                "still in date is accepted."
            ),
            outcome="ok" if valid else "blocked",
            refs=[receive_seq],
            check=Check(
                name="assertion_signature_and_claims",
                rule="verify JWS via issuer JWKS AND iss trusted AND aud=token endpoint AND exp valid",
                expected="valid signature, trusted iss, aud=token endpoint, unexpired",
                actual="all checks passed" if valid else f"rejected ({failure})",
                result="PASS" if valid else "FAIL",
                spec_ref=SpecRef(rfc="RFC 7523", section="§3"),
            ),
            spec_refs=[SpecRef(rfc="RFC 7523", section="§3")],
        )
        if not valid:
            raise OAuthError("invalid_grant", f"assertion verification failed ({failure})", at_seq=verify_seq)

        # One-time-use (jti) check. The store is always maintained, so the server can
        # always see a reused jti; the capability toggle only decides whether it is
        # rejected. On a fresh jti the check passes and the jti is recorded; on a
        # repeat it fails — enforced (rejected) when protection is on, reported but
        # honored when protection is off (the honest-report behaviour, cf. 'state').
        jti = claims.get("jti")
        seen = jti in self._seen_jti
        if not seen:
            jti_outcome = "ok"
        elif self._enforce_replay_protection:
            jti_outcome = "attack_blocked"
        else:
            jti_outcome = "blocked"
        if seen and not self._enforce_replay_protection:
            jti_detail = (
                "This assertion's 'jti' has already been redeemed. Replay protection "
                "is OFF, so although the server can see the reuse it does not reject "
                "it — the replayed assertion is honored anyway."
            )
        elif seen:
            jti_detail = (
                "This assertion's 'jti' has already been redeemed. Replay protection "
                "is ON, so one-time use is enforced and the replay is rejected: a "
                "captured assertion is worthless once its jti has been spent (and its "
                "short 'exp' closes the window regardless)."
            )
        else:
            jti_detail = (
                "The server records this assertion's 'jti' as redeemed. A first "
                "redemption is fine; the same jti presented again is a replay."
            )
        jti_seq = self.recorder.emit(
            actor="auth_server",
            phase="token",
            summary="Token endpoint checks the assertion's jti for one-time use.",
            detail=jti_detail,
            outcome=jti_outcome,
            refs=[verify_seq],
            check=Check(
                name="assertion_jti_single_use",
                rule="assertion jti has not been redeemed before (within its exp window)",
                expected="unused jti",
                actual="unused jti" if not seen else "jti already redeemed (replay)",
                result="PASS" if not seen else "FAIL",
                spec_ref=SpecRef(rfc="RFC 7523", section="§3"),
            ),
            spec_refs=[SpecRef(rfc="RFC 7523", section="§3")],
        )
        if not seen:
            self._seen_jti.add(jti)
        if seen and self._enforce_replay_protection:
            raise OAuthError(
                "invalid_grant", "assertion jti already redeemed (replay)", at_seq=jti_seq
            )

        # DPoP sender-constraining (RFC 9449 §5–§6): bind the token to the proof's
        # key via cnf.jkt. Absent a proof the token is a plain bearer token.
        extra_claims = None
        if request.get("dpop") is not None:
            bound = crypto.verify_dpop_proof(
                request["dpop"], htm="POST", htu=self.env.token_url
            )
            extra_claims = {"cnf": {"jkt": bound["jkt"]}}

        access_token = crypto.sign_access_token(
            self.signing_key,
            issuer=self.env.issuer,
            subject=claims["sub"],
            audience=self.env.resource_audience,
            client_id=iss,
            scope=self.env.client.scope,
            ttl_seconds=300,
            extra_claims=extra_claims,
        )
        self.recorder.emit(
            actor="auth_server",
            phase="token",
            summary="Authorization server issues a signed JWT access token.",
            detail=(
                "The assertion is valid and its jti now spent. The server signs a real "
                "RS256 access token scoped to the assertion's subject and returns it. "
                "The resource server verifies it against the same JWKS as any other "
                "token from this AS."
            ),
            outcome="ok",
            refs=[jti_seq],
            http=HttpExchange(
                request=HttpMessage(method="POST", url=self.env.token_url),
                response=HttpMessage(
                    status=200,
                    headers={"Content-Type": "application/json"},
                    body={
                        "access_token": access_token,
                        "token_type": "Bearer",
                        "expires_in": 300,
                        "scope": self.env.client.scope,
                    },
                ),
                highlight=["response.body.access_token", "response.body.token_type"],
                source_actor="auth_server",
                target_actor=peer,
            ),
            knowledge_delta={"auth_server": KnowledgeState(has=["access_token"])},
            spec_refs=[SpecRef(rfc="RFC 7523", section="§2.1")],
        )
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 300,
            "scope": self.env.client.scope,
        }


class JwtBearerAttacker:
    """The adversary against the JWT bearer grant: capture then replay.

    There is no front channel to intercept a code from; the attack surface is the
    assertion itself. The attacker captures a still-valid assertion off the back
    channel (a proxy or request log, an SSRF, a misconfigured mirror) and replays
    it. Crucially it holds only the assertion, not the issuer's signing key, so it
    cannot mint a fresh one — which is exactly why one-time ``jti`` + short ``exp``
    defeat it.
    """

    def __init__(self, recorder: Recorder, env: Environment):
        self.recorder = recorder
        self.env = env
        self.origin = "https://attacker.evil.internal"
        self._assertion: Optional[str] = None
        self._access_token: Optional[str] = None

    def capture_assertion(self, assertion: str, *, obtained_from_seq: int) -> Dict[str, Any]:
        """Capture a copy of a valid assertion from the back channel."""
        self._assertion = assertion
        seq = self.recorder.emit(
            actor="attacker",
            phase="token",
            summary="Attacker captures a valid JWT assertion.",
            detail=(
                "The assertion travels the back channel to the token endpoint, so a "
                "leak — a proxy or access log, an SSRF, a mirrored request — can expose "
                "it. The attacker captures a copy. It holds the signed assertion but "
                "NOT the issuer's private signing key, so it cannot mint a fresh "
                "assertion with a new jti or a later exp; it can only replay this one."
            ),
            outcome="ok",
            refs=[obtained_from_seq],
            http=HttpExchange(
                request=HttpMessage(
                    method="GET",
                    url=f"{self.origin}/harvest",
                    headers={"X-Observed": "back-channel assertion"},
                ),
                response=HttpMessage(status=200, body={"captured_assertion": "<signed_jwt_assertion>"}),
                highlight=["response.body.captured_assertion"],
                source_actor="client",
                target_actor="attacker",
            ),
            knowledge_delta={
                "attacker": KnowledgeState(
                    has=["jwt_assertion"],
                    lacks=["assertion_signing_key"],
                ),
            },
            spec_refs=[SpecRef(rfc="RFC 7523", section="§3")],
        )
        return {"seq": seq}

    def replay_assertion(self, *, auth_server: JwtBearerAuthServer) -> Dict[str, Any]:
        """Replay the captured assertion at the real token endpoint.

        The outcome is decided by the protocol: with replay protection the genuine
        one-time-``jti`` check rejects the reuse; without it the server honors the
        replay and issues a user-scoped token to the attacker. Returns
        ``{"got_token": bool, "at_seq": int | None}``.
        """
        assert self._assertion is not None, "replay_assertion before capture_assertion"
        token_request = {
            "grant_type": JWT_BEARER_GRANT_TYPE,
            "assertion": self._assertion,
        }
        try:
            with trace_context.acting(on_behalf_of="attacker", source_actor="attacker"):
                token_response = auth_server.token_jwt_bearer(token_request)
        except OAuthError as exc:
            self.recorder.emit(
                actor="attacker",
                phase="token",
                summary="Attacker's assertion replay is rejected.",
                detail=(
                    "The token endpoint rejects the replay. The assertion's signature "
                    "and claims still verify, but its jti was already redeemed and "
                    "one-time use is enforced, so no token is issued. The attacker "
                    "cannot mint a fresh assertion because it lacks the signing key."
                ),
                outcome="attack_blocked",
                refs=[exc.at_seq] if exc.at_seq is not None else [self.recorder.last_seq],
                http=HttpExchange(
                    request=HttpMessage(method="POST", url=self.env.token_url),
                    response=HttpMessage(status=exc.status, body={"error": exc.error}),
                    highlight=["response.body.error"],
                    source_actor="auth_server",
                    target_actor="attacker",
                ),
                spec_refs=[SpecRef(rfc="RFC 7523", section="§3")],
            )
            return {"got_token": False, "at_seq": exc.at_seq}

        self._access_token = token_response["access_token"]
        seq = self.recorder.emit(
            actor="attacker",
            phase="token",
            summary="Attacker obtains a user-scoped token by replaying the assertion.",
            detail=(
                "Without replay protection the token endpoint honored the reused "
                "assertion: a captured, still-valid assertion was all that was needed. "
                "The attacker now holds an access token scoped to the user's subject."
            ),
            outcome="attack_success",
            refs=[self.recorder.last_seq],
            knowledge_delta={"attacker": KnowledgeState(has=["access_token"])},
            spec_refs=[SpecRef(rfc="RFC 7523", section="§3")],
        )
        return {"got_token": True, "at_seq": seq}

    def access_resource(self, *, resource_server: ResourceServer) -> Dict[str, Any]:
        """Use the replayed-flow token to read the user's protected data."""
        assert self._access_token is not None, "access_resource without a token"
        request = {
            "url": self.env.resource_url,
            "headers": {"Authorization": f"Bearer {self._access_token}"},
        }
        with trace_context.acting(on_behalf_of="attacker", source_actor="attacker"):
            return resource_server.get_resource(request)
