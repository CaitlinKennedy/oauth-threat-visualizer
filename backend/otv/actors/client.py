"""The legitimate relying party (client).

Exposed as a documented service-API interface (:class:`Client`) whose public
methods are named for the RP's real actions; :class:`ClientImpl` hides the
detail. The interface is pure protocol — methods take only domain arguments;
correlation metadata (``on_behalf_of``, causal ``refs``) is captured out-of-band
via the ambient trace context, and the client remembers the ``seq`` of its own
prior events internally rather than receiving them across the seam. So promoting
any actor to a standalone REST service later is a transport swap, not a change to
callers or the contract.

Phase 0 is a confidential client with no PKCE (added in Phase 1).
"""

from __future__ import annotations

import abc
from typing import Any, Dict, Optional

from .. import crypto
from ..contract import Check, HttpExchange, HttpMessage, KnowledgeState, SpecRef
from ..recorder import Recorder
from .auth_server import AuthServer
from .environment import Environment
from .resource_server import ResourceServer


class Client(abc.ABC):
    """Service-API interface for the relying party."""

    @abc.abstractmethod
    def start_authorization(self) -> Dict[str, Any]:
        """Begin the authorization-code flow.

        Builds the authorization request and records the step. Returns
        ``{"params": <authorization request>, "seq": <event seq>}``.
        """

    @abc.abstractmethod
    def receive_redirect(self, redirect: Dict[str, Any]) -> Dict[str, Any]:
        """Handle the authorization response redirect and validate ``state``.

        Returns ``{"code": <authorization code>, "state_ok": bool,
        "seq": <event seq>}``.
        """

    @abc.abstractmethod
    def exchange_code(self, code: str, *, auth_server: "AuthServer") -> Dict[str, Any]:
        """Redeem the code at the authorization server's token endpoint.

        Performs the real back-channel exchange via the ``AuthServer`` interface
        and stores the resulting access token. Returns
        ``{"token_response": {...}, "seq": <event seq>}``.
        """

    @abc.abstractmethod
    def access_resource(self, *, resource_server: "ResourceServer") -> Dict[str, Any]:
        """Call the protected resource with the stored access token.

        Returns ``{"ok": bool, "resource": {...} | None, "seq": <event seq>}``.
        """


class ClientImpl(Client):
    def __init__(
        self,
        recorder: Recorder,
        env: Environment,
        *,
        pkce_method: Optional[str] = None,
        registered_client=None,
        enforce_state: bool = False,
        dpop: bool = False,
    ):
        self.recorder = recorder
        self.env = env
        # The registered client this instance represents. Defaults to the
        # confidential web client (the happy path); the injection scenario passes
        # the public client so PKCE is honestly the lone gate.
        self.registered = registered_client or env.client
        # A per-flow anti-CSRF value bound to this browser session. When the
        # 'state' capability is active (``enforce_state``), a returned state that
        # does not match this value is REJECTED on the redirect; when inactive, the
        # mismatch is reported honestly but not enforced (RFC 6749 §10.12).
        self.state = crypto.new_opaque_token(prefix="st_")
        self.enforce_state = enforce_state
        # PKCE (RFC 7636): when the capability is active, the client generates a
        # real per-request verifier and derives the challenge it sends to the AS.
        # The verifier never leaves the client until the back-channel token
        # exchange — that secrecy is exactly what defeats code injection.
        self.pkce_method: Optional[str] = pkce_method
        self.code_verifier: Optional[str] = None
        self.code_challenge: Optional[str] = None
        if pkce_method:
            self.code_verifier = crypto.new_code_verifier()
            self.code_challenge = crypto.code_challenge_for(self.code_verifier, pkce_method)
        self._access_token: Optional[str] = None
        # DPoP (RFC 9449): when active, the client holds a proof-of-possession key.
        # It presents a DPoP proof with the token exchange (so the AS binds the
        # token to this key via cnf.jkt) and with every resource call. The private
        # key never leaves the client — that secrecy is what defeats token replay.
        self.dpop_key: Optional[crypto.DpopKey] = crypto.DpopKey.generate() if dpop else None
        # The seq of this client's own authorization request, remembered so the
        # redirect-receipt step can causally reference it without the seq being
        # passed across the interface.
        self._request_seq: Optional[int] = None

    def start_authorization(self) -> Dict[str, Any]:
        client = self.registered
        params: Dict[str, Any] = {
            "response_type": "code",
            "client_id": client.client_id,
            "redirect_uri": client.redirect_uri,
            "scope": client.scope,
            "state": self.state,
        }
        highlight = ["request.body.response_type", "request.body.state"]
        has = (
            ["state", "redirect_uri", "client_credentials"]
            if not client.is_public
            else ["state", "redirect_uri", "client_id"]
        )
        detail = (
            "The client builds an authorization request and redirects the user's "
            "browser to the authorization server. It asks for an authorization "
            "'code' (not a token directly) and includes a 'state' value to tie the "
            "eventual response back to this browser session."
        )
        if self.pkce_method:
            params["code_challenge"] = self.code_challenge
            params["code_challenge_method"] = self.pkce_method
            highlight.append("request.body.code_challenge")
            # The client holds the secret verifier; only the challenge goes on the wire.
            has += ["code_verifier", "code_challenge"]
            detail += (
                " Because PKCE is enabled, the client also generates a secret "
                "code_verifier, keeps it, and sends only its S256 code_challenge — "
                "binding the eventual code to this specific client instance."
            )
        seq = self.recorder.emit(
            actor="client",
            phase="authorize",
            summary="Client starts the authorization-code flow.",
            detail=detail,
            outcome="ok",
            http=HttpExchange(
                request=HttpMessage(
                    method="GET",
                    url=self.env.authorize_url,
                    body=params,
                ),
                response=HttpMessage(status=302, body={"redirecting_to": "authorization_server"}),
                highlight=highlight,
                source_actor="client",
                target_actor="auth_server",
            ),
            knowledge_delta={
                "client": KnowledgeState(has=has),
            },
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.1")],
        )
        self._request_seq = seq
        return {"params": params, "seq": seq}

    def receive_redirect(self, redirect: Dict[str, Any]) -> Dict[str, Any]:
        code = redirect["code"]
        returned_state = redirect.get("state")
        state_ok = returned_state == self.state
        # Honest outcome: a state mismatch is never an "ok" step. When the 'state'
        # capability is active it is ENFORCED (the client rejects and does not
        # redeem — "attack_blocked"); when inactive the mismatch is reported
        # truthfully but not enforced ("blocked"), the P1 honest-report behavior.
        if state_ok:
            state_detail = (
                "The client confirms the 'state' matches the one it generated, so the "
                "response belongs to the session it started."
            )
            outcome = "ok"
        elif self.enforce_state:
            state_detail = (
                "The returned 'state' does NOT match the one the client generated. "
                "Because the 'state' check is enforced, the client REJECTS the response "
                "and does not redeem the code — this is exactly the cross-session code "
                "injection (login CSRF) that binding the response to the session prevents."
            )
            outcome = "attack_blocked"
        else:
            state_detail = (
                "The returned 'state' does NOT match the one the client generated — "
                "the response cannot be tied to the session that started the flow, which "
                "is the signature of CSRF or a cross-session code injection."
            )
            outcome = "blocked"
        detail = (
            "The browser lands back on the client's redirect URI carrying the code "
            "and the echoed 'state'. " + state_detail
        )
        seq = self.recorder.emit(
            actor="client",
            phase="redirect",
            summary="Client receives the authorization code on its redirect URI.",
            detail=detail,
            outcome=outcome,
            # Non-linear causal anchor: this depends on the client's own original
            # request, remembered internally rather than passed across the seam.
            refs=[self._request_seq] if self._request_seq is not None else [],
            http=HttpExchange(
                request=HttpMessage(
                    method="GET",
                    url=f"{self.registered.redirect_uri}?code={code}&state={returned_state}",
                ),
                response=HttpMessage(status=200, body={"state_valid": state_ok}),
                highlight=["response.body.state_valid"],
                source_actor="client",
                target_actor="client",
            ),
            check=Check(
                name="state_matches_session",
                rule="returned state == state the client generated",
                expected=self.state,
                actual=returned_state if returned_state is not None else "(absent)",
                result="PASS" if state_ok else "FAIL",
                spec_ref=SpecRef(rfc="RFC 6749", section="§10.12"),
            ),
            knowledge_delta={
                "client": KnowledgeState(has=["authorization_code"]),
            },
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.2")],
        )
        # ``blocked`` is True only when an active 'state' check rejected the
        # response; a caller (a runner) uses it to stop before redemption.
        return {
            "code": code,
            "state_ok": state_ok,
            "blocked": self.enforce_state and not state_ok,
            "seq": seq,
        }

    def exchange_code(self, code: str, *, auth_server: "AuthServer") -> Dict[str, Any]:
        client = self.registered
        token_request: Dict[str, Any] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": client.redirect_uri,
            "client_id": client.client_id,
        }
        if client.client_secret is not None:
            token_request["client_secret"] = client.client_secret
        if self.pkce_method:
            # Present the secret verifier now, over the back channel, so the AS can
            # recompute the challenge and confirm this is the same client instance.
            token_request["code_verifier"] = self.code_verifier
        if self.dpop_key is not None:
            # A DPoP proof for the token endpoint (htm=POST, htu=token URL). The AS
            # binds the issued token to this key's thumbprint (cnf.jkt).
            token_request["dpop"] = crypto.create_dpop_proof(
                self.dpop_key, htm="POST", htu=self.env.token_url
            )
        # Real back-channel call through the AuthServer *interface* (pure protocol:
        # no trace-plumbing crosses the seam).
        token_response = auth_server.token(token_request)
        self._access_token = token_response["access_token"]
        seq = self.recorder.emit(
            actor="client",
            phase="token",
            summary="Client receives and stores the access token.",
            detail=(
                "The token exchange succeeds. The client now holds a signed, "
                "audience-scoped access token it can present to the resource server on "
                "the user's behalf."
            ),
            outcome="ok",
            knowledge_delta={
                "client": KnowledgeState(has=["access_token"]),
            },
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.4")],
        )
        return {"token_response": token_response, "seq": seq}

    def access_resource(self, *, resource_server: "ResourceServer") -> Dict[str, Any]:
        if self._access_token is None:
            raise RuntimeError("access_resource called before a token was obtained")
        if self.dpop_key is not None:
            # A sender-constrained call: present the token under the DPoP scheme and
            # a fresh proof (htm=GET, htu=resource URL) the RS binds to the token.
            request = {
                "url": self.env.resource_url,
                "headers": {
                    "Authorization": f"DPoP {self._access_token}",
                    "DPoP": crypto.create_dpop_proof(
                        self.dpop_key, htm="GET", htu=self.env.resource_url
                    ),
                },
            }
        else:
            request = {
                "url": self.env.resource_url,
                "headers": {"Authorization": f"Bearer {self._access_token}"},
            }
        # Real call through the ResourceServer *interface*.
        return resource_server.get_resource(request)
