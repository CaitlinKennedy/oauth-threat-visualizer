"""Per-scenario orchestration runners (the plugin seam).

Each scenario/attack orchestration lives in its own discoverable module here and
**self-registers** a :class:`Runner` at import time, instead of a growing
``if/elif`` in the conductor. A runner declares a ``matches(config)`` predicate
and a ``run(config) -> Trace`` orchestration. :func:`load_all` imports every
module in this package (filename order); :func:`select` returns the first
registered runner whose predicate matches a config.

**To add a scenario in a later phase:** drop a new module here that builds a
:class:`Runner` and calls :func:`register` at module scope. Nothing else — the
conductor discovers it automatically. Filename order (``r<n>_*``) is the
match-precedence order; matchers are otherwise mutually exclusive (each keys off a
distinct active attack, and the happy-path runner keys off *no* active attack).
"""

from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass
from typing import Callable, List, Optional

from ...contract import ScenarioConfig, Trace


@dataclass(frozen=True)
class Runner:
    """A named scenario orchestration behind a config predicate."""

    id: str
    matches: Callable[[ScenarioConfig], bool]
    run: Callable[[ScenarioConfig], Trace]


_RUNNERS: List[Runner] = []
_loaded = False


def register(runner: Runner) -> Runner:
    """Add a runner to the ordered registry (called from a runner module)."""
    if any(r.id == runner.id for r in _RUNNERS):
        raise ValueError(f"duplicate runner id {runner.id!r}")
    _RUNNERS.append(runner)
    return runner


def load_all() -> None:
    """Import every runner module in this package exactly once (idempotent)."""
    global _loaded
    if _loaded:
        return
    for mod in sorted(m.name for m in pkgutil.iter_modules(__path__)):
        importlib.import_module(f"{__name__}.{mod}")
    _loaded = True


def all_runners() -> List[Runner]:
    load_all()
    return list(_RUNNERS)


def select(config: ScenarioConfig) -> Optional[Runner]:
    """The first registered runner whose predicate matches ``config``."""
    for runner in all_runners():
        if runner.matches(config):
            return runner
    return None
