"""Ambient trace context — the out-of-band recording seam.

The actor **service-API** interfaces (``AuthServer.token(request)``,
``ResourceServer.get_resource(request)``, …) are pure protocol: their signatures
carry only domain arguments, never trace-plumbing like ``on_behalf_of`` or
``refs``. Correlation metadata that a real REST deployment would carry in
headers / an ambient request scope is instead threaded here, through a
:class:`contextvars.ContextVar`, so it is captured *around* an actor call rather
than passed *across* the interface.

The conductor wraps each actor interaction in :func:`acting`; the
:class:`~otv.recorder.Recorder` reads the current ``on_behalf_of`` (and optional
``actor_instance``) from this context when it stamps an event. Causal ``refs``
are derived by the recorder itself (a linear chain by default), with actors
supplying an explicit anchor only for a non-linear dependency they remember
internally — again, never through the interface.

This keeps the future four-standalone-servers swap clean: a REST transport that
satisfies the same interfaces needs no extra parameters, because the seam never
grew any.
"""

from __future__ import annotations

import contextvars
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator, Optional


@dataclass(frozen=True)
class TraceFrame:
    """The ambient correlation facts in scope for the current actor call.

    ``source_actor`` is the peer that originated the inbound request an actor is
    handling — in a real REST deployment this is the TCP/authenticated peer, i.e.
    ambient request scope, not a protocol field. An endpoint (e.g. the token
    endpoint) reads it to stamp the ``source_actor`` of the receive step, so the
    same ``AuthServer.token(request)`` serves the honest client and the attacker
    without the caller identity crossing the pure-protocol interface. ``None``
    means "the default legitimate client" so the happy path is unchanged.

    ``as_user`` is the identity authenticated in the current browser session — the
    account the authorization endpoint logs in and mints a code for. Like a login
    cookie, it is ambient session state, not a protocol field, so it lives here
    rather than in ``authorize``'s signature. ``None`` means the environment's
    default user, keeping the happy path and injection unchanged; the CSRF scenario
    sets it to the *attacker's* account (the attacker consenting for themselves).
    """

    on_behalf_of: str = "user"
    actor_instance: Optional[str] = None
    source_actor: Optional[str] = None
    as_user: Optional[Any] = None


_current: contextvars.ContextVar[Optional[TraceFrame]] = contextvars.ContextVar(
    "otv_trace_frame", default=None
)


@contextmanager
def acting(
    *,
    on_behalf_of: str = "user",
    actor_instance: Optional[str] = None,
    source_actor: Optional[str] = None,
    as_user: Optional[Any] = None,
) -> Iterator[None]:
    """Scope the ambient trace frame for the duration of an actor interaction.

    Frames nest: a chained-attack stage can enter ``acting(on_behalf_of=...)``
    inside another, and the previous frame is restored on exit. ``source_actor``
    names the peer that originated the request being handled (e.g. ``"attacker"``
    for an injected token redemption); leave it unset for the honest client.
    ``as_user`` names the account authenticated in the current session (the CSRF
    scenario logs in the attacker's own account); leave it unset for the default
    user.
    """
    token = _current.set(
        TraceFrame(
            on_behalf_of=on_behalf_of,
            actor_instance=actor_instance,
            source_actor=source_actor,
            as_user=as_user,
        )
    )
    try:
        yield
    finally:
        _current.reset(token)


def current_frame() -> TraceFrame:
    """The frame in scope, or a default ``user`` frame outside any :func:`acting`."""
    return _current.get() or TraceFrame()


def current_on_behalf_of() -> str:
    return current_frame().on_behalf_of


def current_actor_instance() -> Optional[str]:
    return current_frame().actor_instance


def current_source_actor() -> Optional[str]:
    """The peer originating the current inbound request, or ``None`` if unset."""
    return current_frame().source_actor


def current_as_user() -> Optional[Any]:
    """The account authenticated in the current session, or ``None`` if unset."""
    return current_frame().as_user
