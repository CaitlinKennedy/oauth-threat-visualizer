"""The legitimate relying party (client).

Exposed as a documented service-API interface (:class:`Client`) whose public
methods are named for the RP's real actions; :class:`ClientImpl` hides the
detail. Callers depend only on the interface, and the client reaches the
authorization and resource servers only through *their* interfaces — so
promoting any actor to a standalone REST service later is a transport swap, not
a change to callers or the contract.

Phase 0 is a confidential client with no PKCE (added in Phase 1).
"""

from __future__ import annotations

import abc
from typing import Any, Dict

from .. import crypto
from ..contract import HttpExchange, HttpMessage, KnowledgeState, SpecRef
from ..recorder import Recorder
from .auth_server import AuthServer
from .environment import Environment
from .resource_server import ResourceServer


class Client(abc.ABC):
    """Service-API interface for the relying party."""

    @abc.abstractmethod
    def start_authorization(self, *, on_behalf_of: str = "user") -> Dict[str, Any]:
        """Begin the authorization-code flow.

        Builds the authorization request and records the step. Returns
        ``{"params": <authorization request>, "seq": <event seq>}``.
        """

    @abc.abstractmethod
    def receive_redirect(
        self, redirect: Dict[str, Any], *, request_seq: int, on_behalf_of: str = "user"
    ) -> Dict[str, Any]:
        """Handle the authorization response redirect and validate ``state``.

        Returns ``{"code": <authorization code>, "seq": <event seq>}``.
        """

    @abc.abstractmethod
    def exchange_code(
        self,
        code: str,
        *,
        redirect_seq: int,
        auth_server: "AuthServer",
        on_behalf_of: str = "user",
    ) -> Dict[str, Any]:
        """Redeem the code at the authorization server's token endpoint.

        Performs the real back-channel exchange via the ``AuthServer`` interface
        and stores the resulting access token. Returns
        ``{"token_response": {...}, "seq": <event seq>}``.
        """

    @abc.abstractmethod
    def access_resource(
        self,
        *,
        token_seq: int,
        resource_server: "ResourceServer",
        on_behalf_of: str = "user",
    ) -> Dict[str, Any]:
        """Call the protected resource with the stored access token.

        Returns ``{"ok": bool, "resource": {...} | None, "seq": <event seq>}``.
        """


class ClientImpl(Client):
    def __init__(self, recorder: Recorder, env: Environment):
        self.recorder = recorder
        self.env = env
        # A per-flow anti-CSRF value. The 'state' capability (binding the
        # response to the session) is exercised fully in a later phase; the
        # client already generates and echoes it here.
        self.state = crypto.new_opaque_token(prefix="st_")
        self._access_token: str | None = None

    def start_authorization(self, *, on_behalf_of: str = "user") -> Dict[str, Any]:
        client = self.env.client
        params = {
            "response_type": "code",
            "client_id": client.client_id,
            "redirect_uri": client.redirect_uri,
            "scope": client.scope,
            "state": self.state,
        }
        seq = self.recorder.emit(
            actor="client",
            on_behalf_of=on_behalf_of,
            phase="authorize",
            summary="Client starts the authorization-code flow.",
            detail=(
                "The client builds an authorization request and redirects the user's "
                "browser to the authorization server. It asks for an authorization "
                "'code' (not a token directly) and includes a 'state' value to tie the "
                "eventual response back to this browser session."
            ),
            outcome="ok",
            http=HttpExchange(
                request=HttpMessage(
                    method="GET",
                    url=self.env.authorize_url,
                    body=params,
                ),
                response=HttpMessage(status=302, body={"redirecting_to": "authorization_server"}),
                highlight=["response_type", "state"],
            ),
            knowledge_delta={
                "client": KnowledgeState(has=["state", "redirect_uri", "client_credentials"]),
            },
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.1")],
        )
        return {"params": params, "seq": seq}

    def receive_redirect(
        self, redirect: Dict[str, Any], *, request_seq: int, on_behalf_of: str = "user"
    ) -> Dict[str, Any]:
        code = redirect["code"]
        returned_state = redirect.get("state")
        state_ok = returned_state == self.state
        seq = self.recorder.emit(
            actor="client",
            on_behalf_of=on_behalf_of,
            phase="redirect",
            summary="Client receives the authorization code on its redirect URI.",
            detail=(
                "The browser lands back on the client's redirect URI carrying the code "
                "and the echoed 'state'. The client confirms the 'state' matches the one "
                "it generated, so the response belongs to the session it started."
            ),
            outcome="ok",
            refs=[request_seq],
            http=HttpExchange(
                request=HttpMessage(
                    method="GET",
                    url=f"{self.env.client.redirect_uri}?code={code}&state={returned_state}",
                ),
                response=HttpMessage(status=200, body={"state_valid": state_ok}),
                highlight=["code", "state"],
            ),
            knowledge_delta={
                "client": KnowledgeState(has=["authorization_code"]),
            },
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.2")],
        )
        return {"code": code, "seq": seq}

    def exchange_code(
        self,
        code: str,
        *,
        redirect_seq: int,
        auth_server: "AuthServer",
        on_behalf_of: str = "user",
    ) -> Dict[str, Any]:
        client = self.env.client
        token_request = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": client.redirect_uri,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
        }
        # Real back-channel call through the AuthServer *interface*.
        token_response = auth_server.token(
            token_request, on_behalf_of=on_behalf_of, refs=[redirect_seq]
        )
        self._access_token = token_response["access_token"]
        token_endpoint_seq = self.recorder.last_seq
        seq = self.recorder.emit(
            actor="client",
            on_behalf_of=on_behalf_of,
            phase="token",
            summary="Client receives and stores the access token.",
            detail=(
                "The token exchange succeeds. The client now holds a signed, "
                "audience-scoped access token it can present to the resource server on "
                "the user's behalf."
            ),
            outcome="ok",
            refs=[token_endpoint_seq],
            knowledge_delta={
                "client": KnowledgeState(has=["access_token"]),
            },
            spec_refs=[SpecRef(rfc="RFC 6749", section="§4.1.4")],
        )
        return {"token_response": token_response, "seq": seq}

    def access_resource(
        self,
        *,
        token_seq: int,
        resource_server: "ResourceServer",
        on_behalf_of: str = "user",
    ) -> Dict[str, Any]:
        if self._access_token is None:
            raise RuntimeError("access_resource called before a token was obtained")
        request = {
            "url": self.env.resource_url,
            "headers": {"Authorization": f"Bearer {self._access_token}"},
        }
        # Real call through the ResourceServer *interface*.
        return resource_server.get_resource(
            request, refs=[token_seq], on_behalf_of=on_behalf_of
        )
