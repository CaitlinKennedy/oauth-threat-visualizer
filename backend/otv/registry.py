"""The typed capability / attack registry.

The on-the-wire config is an OPEN id-keyed map (see ``contract.FeatureState``),
but every id is backed here by a small, self-documenting class: its id, label,
description, governing spec, parameter schema, default state, and
incompatibilities. ``GET /api/catalog`` is just this registry serialized, so the
UI picker is data-driven and never edited when a capability or attack is added.

Extension point (the plugin seam)
---------------------------------
Capabilities and attacks are **self-registering modules**. Each lives in its own
file under :mod:`otv.catalog` and, at import time, calls :func:`capability` or
:func:`attack` to add itself to the catalog. There is no hand-edited central
list: :mod:`otv.catalog` auto-discovers and imports every module in that package,
so *adding a capability or attack is just adding a file there* — no edit to this
module or any shared list. Each item carries an explicit ``order`` that fixes its
place in the catalog (and therefore the picker), independent of filename.

The wire schema is frozen; this registry lists the features the build ships.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .contract import SpecRef


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
    # Explicit catalog position (ascending), ties broken by id. Fixes the picker
    # order independent of filename, so renaming a module never reorders the UI.
    order: int = 100
    default_active: bool = False
    params: List[ParamSpec] = field(default_factory=list)
    incompatibilities: List[str] = field(default_factory=list)
    # Grant ids this item applies to; empty = all grants. Lets the picker hide,
    # e.g., PKCE for a grant that has no front channel.
    applies_to_grants: List[str] = field(default_factory=list)
    # Meta-capability bundling (IMPLEMENTATION.md §3): ``implies`` ids are forced
    # active + locked when this item is active; ``forbids`` ids are disallowed. A
    # ``forbids`` entry may name a capability id OR a grant id (so a bundling
    # capability could forbid the ``implicit`` grant). Both empty for a plain item.
    implies: List[str] = field(default_factory=list)
    forbids: List[str] = field(default_factory=list)
    # Names of the first-class ``Check``s (contract.Check.name) this item's own
    # enforcement emits. Lets a check-to-capability attribution (e.g. "which
    # toggle blocked this run?") be DERIVED by scanning the registry instead of
    # living in a hand-maintained central map — see
    # ``engine.runners.support.CHECK_TO_CAPABILITY``. Empty for an item that
    # emits no first-class check (e.g. an attack).
    check_names: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "description": self.description,
            "spec_ref": {"rfc": self.spec_ref.rfc, "section": self.spec_ref.section},
            "kind": self.kind,
            "default_active": self.default_active,
            "params": [p.to_dict() for p in self.params],
            "incompatibilities": list(self.incompatibilities),
            "applies_to_grants": list(self.applies_to_grants),
            "implies": list(self.implies),
            "forbids": list(self.forbids),
            "check_names": list(self.check_names),
        }


class Capability(RegistryItem):
    pass


class Attack(RegistryItem):
    pass


# --- The self-registration seam --------------------------------------------
# Feature modules under ``otv.catalog`` call ``capability(...)`` / ``attack(...)``
# at import time. The public views below are sorted by each item's explicit
# ``order`` (ties broken by id), which is what ``to_catalog_dict`` — and therefore
# the picker — renders in, so module import order never affects the UI.

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

# Fix the catalog order by each item's explicit ``order`` (ties broken by id) so
# it is deterministic and independent of module import order.
_CAPABILITIES.sort(key=lambda i: (i.order, i.id))
_ATTACKS.sort(key=lambda i: (i.order, i.id))

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
