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
from typing import Iterator, Optional


@dataclass(frozen=True)
class TraceFrame:
    """The ambient correlation facts in scope for the current actor call."""

    on_behalf_of: str = "user"
    actor_instance: Optional[str] = None


_current: contextvars.ContextVar[Optional[TraceFrame]] = contextvars.ContextVar(
    "otv_trace_frame", default=None
)


@contextmanager
def acting(
    *, on_behalf_of: str = "user", actor_instance: Optional[str] = None
) -> Iterator[None]:
    """Scope the ambient trace frame for the duration of an actor interaction.

    Frames nest: a chained-attack stage can enter ``acting(on_behalf_of=...)``
    inside another, and the previous frame is restored on exit.
    """
    token = _current.set(
        TraceFrame(on_behalf_of=on_behalf_of, actor_instance=actor_instance)
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
