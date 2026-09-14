"""The typed capability / attack registry.

The on-the-wire config is an OPEN id-keyed map (see ``contract.FeatureState``),
but every id is backed here by a small, self-documenting class: its id, label,
description, governing spec, parameter schema, default state, incompatibilities,
and the phase it arrives in. ``GET /api/catalog`` is just this registry
serialized, so the UI picker is data-driven and never edited when a capability
or attack is added.

Extension point (the plugin seam)
---------------------------------
Capabilities and attacks are **self-registering modules**. Each lives in its own
file under :mod:`otv.catalog` and, at import time, calls :func:`capability` or
:func:`attack` to add itself to the catalog. There is no hand-edited central
list: :mod:`otv.catalog` auto-discovers and imports every module in that package
(ordered by filename), so *adding a capability or attack in a later phase is just
adding a file there* — no edit to this module or any shared list.

The wire schema is frozen; this registry is what grows per phase.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .contract import SpecRef

# The highest phase whose capabilities/attacks are actually runnable in this
# build. ``RegistryItem.available`` is derived from it, so shipping a new phase is
# a one-line bump here rather than edits scattered across items. Phase 5 makes the
# ``client_auth`` capability and the ``static_secret_leak`` attack runnable (on top
# of Phases 1–2's ``pkce`` / ``auth_code_injection`` and ``state`` / replay / CSRF);
# every later toggle (``dpop``, ``issuer_id``, ``phish*``) stays unavailable until
# its own phase lands.
CURRENT_PHASE = 5


@dataclass(frozen=True)
class ParamSpec:
    """One parameter a feature accepts, for the picker and light validation."""

    name: str
    type: str  # "string" | "bool" | "enum"
    default: Any
    description: str
    choices: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "type": self.type,
            "default": self.default,
            "description": self.description,
        }
        if self.choices:
            d["choices"] = list(self.choices)
        return d


@dataclass(frozen=True)
class RegistryItem:
    """Base for a catalogued capability or attack."""

    id: str
    label: str
    description: str
    spec_ref: SpecRef
    kind: str  # "capability" | "attack"
    phase: int  # the phase in which this becomes runnable
    default_active: bool = False
    params: List[ParamSpec] = field(default_factory=list)
    incompatibilities: List[str] = field(default_factory=list)
    # Grant ids this item applies to; empty = all grants. Lets the picker hide,
    # e.g., PKCE for a grant that has no front channel.
    applies_to_grants: List[str] = field(default_factory=list)
    # Meta-capability bundling (IMPLEMENTATION.md §3): ``implies`` ids are forced
    # active + locked when this item is active; ``forbids`` ids are disallowed. A
    # ``forbids`` entry may name a capability id OR a grant id (so a future
    # ``oauth_2_1`` can forbid the ``implicit`` grant). Both empty for a plain item.
    implies: List[str] = field(default_factory=list)
    forbids: List[str] = field(default_factory=list)
    # Names of the first-class ``Check``s (contract.Check.name) this item's own
    # enforcement emits. Lets a check-to-capability attribution (e.g. "which
    # toggle blocked this run?") be DERIVED by scanning the registry instead of
    # living in a hand-maintained central map — see
    # ``engine.runners.support.CHECK_TO_CAPABILITY``. Empty for an item that
    # emits no first-class check (e.g. an attack).
    check_names: List[str] = field(default_factory=list)

    @property
    def available(self) -> bool:
        """Runnable in the current build (phase at or below ``CURRENT_PHASE``)."""
        return self.phase <= CURRENT_PHASE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "description": self.description,
            "spec_ref": {"rfc": self.spec_ref.rfc, "section": self.spec_ref.section},
            "kind": self.kind,
            "phase": self.phase,
            "default_active": self.default_active,
            "params": [p.to_dict() for p in self.params],
            "incompatibilities": list(self.incompatibilities),
            "applies_to_grants": list(self.applies_to_grants),
            "implies": list(self.implies),
            "forbids": list(self.forbids),
            "check_names": list(self.check_names),
            "available": self.available,
        }


class Capability(RegistryItem):
    pass


class Attack(RegistryItem):
    pass


# --- The self-registration seam --------------------------------------------
# Feature modules under ``otv.catalog`` call ``capability(...)`` / ``attack(...)``
# at import time. Insertion order within each kind is the module discovery order
# (filename-sorted, see otv/catalog/__init__.py), which is what ``to_catalog_dict``
# — and therefore the picker — renders in.

_CAPABILITIES: List[Capability] = []
_ATTACKS: List[Attack] = []
_BY_ID: Dict[str, RegistryItem] = {}


def _register(item: RegistryItem) -> RegistryItem:
    if item.id in _BY_ID:
        raise ValueError(f"duplicate registry id {item.id!r}")
    _BY_ID[item.id] = item
    if item.kind == "capability":
        _CAPABILITIES.append(item)  # type: ignore[arg-type]
    else:
        _ATTACKS.append(item)  # type: ignore[arg-type]
    return item


def capability(**kw: Any) -> Capability:
    """Define and register a capability. Called from a self-registering module."""
    return _register(Capability(kind="capability", **kw))  # type: ignore[return-value]


def attack(**kw: Any) -> Attack:
    """Define and register an attack. Called from a self-registering module."""
    return _register(Attack(kind="attack", **kw))  # type: ignore[return-value]


# Trigger discovery: importing the package auto-imports every feature module,
# each of which self-registers via the helpers above. This is the only line that
# needs to know features exist; the individual items are never listed here.
from . import catalog as _catalog  # noqa: E402  (import for its registration side effects)

_catalog.load_all()

# Public, ordered views used across the backend and the tests.
CAPABILITIES: List[Capability] = _CAPABILITIES
ATTACKS: List[Attack] = _ATTACKS


def get(item_id: str) -> RegistryItem | None:
    return _BY_ID.get(item_id)


def to_catalog_dict() -> Dict[str, Any]:
    """The payload for ``GET /api/catalog``."""
    return {
        "capabilities": [c.to_dict() for c in CAPABILITIES],
        "attacks": [a.to_dict() for a in ATTACKS],
    }
