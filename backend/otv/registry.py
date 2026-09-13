"""The typed capability / attack registry.

The on-the-wire config is an OPEN id-keyed map (see ``contract.FeatureState``),
but every id is backed here by a small, self-documenting class: its id, label,
description, governing spec, parameter schema, default state, incompatibilities,
and the phase it arrives in. ``GET /api/catalog`` is just this registry
serialized, so the UI picker is data-driven and never edited when a capability
or attack is added — a new feature is a new class here plus its enforcement hook
in the actors.

The wire schema is frozen; this registry is what grows per phase.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .contract import SpecRef

# The highest phase whose capabilities/attacks are actually runnable in this
# build. ``RegistryItem.available`` is derived from it, so shipping a new phase is
# a one-line bump here rather than edits scattered across items. Phase 0 ships the
# happy path only; every catalogued toggle arrives in a later phase.
CURRENT_PHASE = 0


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
            "available": self.available,
        }


class Capability(RegistryItem):
    pass


class Attack(RegistryItem):
    pass


def _cap(**kw: Any) -> Capability:
    return Capability(kind="capability", **kw)


def _atk(**kw: Any) -> Attack:
    return Attack(kind="attack", **kw)


# --- The catalogue (DESIGN.md §4 capabilities, §5 attacks) ------------------
# Phase numbers say when each becomes runnable; Phase 0 ships the roadmap so the
# picker shows what is coming.

CAPABILITIES: List[Capability] = [
    _cap(
        id="pkce",
        label="PKCE",
        description="Bind the authorization code to a per-request verifier (S256).",
        spec_ref=SpecRef(rfc="RFC 7636", section="§4"),
        phase=1,
        applies_to_grants=["authorization_code"],
        params=[
            ParamSpec(
                name="method",
                type="enum",
                default="S256",
                description="Code challenge method.",
                choices=["S256", "plain"],
            )
        ],
    ),
    _cap(
        id="state",
        label="state parameter",
        description="Bind the response to the user's session (anti-CSRF).",
        spec_ref=SpecRef(rfc="RFC 6749", section="§10.12"),
        phase=2,
        applies_to_grants=["authorization_code"],
    ),
    _cap(
        id="dpop",
        label="DPoP",
        description="Sender-constrained tokens via a proof-of-possession key.",
        spec_ref=SpecRef(rfc="RFC 9449", section="§4"),
        phase=6,
        # Sender-constraining applies to any grant that yields a token.
        applies_to_grants=[],
    ),
    _cap(
        id="issuer_id",
        label="AS Issuer Identification",
        description="The AS returns its iss in the authorization response (mix-up defense).",
        spec_ref=SpecRef(rfc="RFC 9207", section="§2"),
        phase=7,
        applies_to_grants=["authorization_code"],
    ),
]

ATTACKS: List[Attack] = [
    _atk(
        id="auth_code_injection",
        label="Auth-code injection",
        description="Inject an attacker-obtained code into a victim's session.",
        spec_ref=SpecRef(rfc="RFC 9700", section="§4.5"),
        phase=1,
        applies_to_grants=["authorization_code"],
        incompatibilities=[],
    ),
    _atk(
        id="code_token_replay",
        label="Auth-code / token replay",
        description="Reuse a captured code or token a second time.",
        spec_ref=SpecRef(rfc="RFC 6819", section="§4.4.1.1"),
        phase=2,
        # Code replay is auth-code-specific; token replay applies to any grant, so
        # this item is not restricted to a single grant.
        applies_to_grants=[],
    ),
    _atk(
        id="static_secret_leak",
        label="Static-secret leak",
        description="A never-rotating client secret is captured and reused.",
        spec_ref=SpecRef(rfc="RFC 6749", section="§10.3"),
        phase=5,
        applies_to_grants=["client_credentials"],
    ),
    _atk(
        id="phishing",
        label="Phishing / smishing",
        description="A fake login/consent lure harvests credentials or a code.",
        spec_ref=SpecRef(rfc="RFC 6819", section="§4.4.1.9"),
        phase=7,
        applies_to_grants=["authorization_code"],
    ),
    _atk(
        id="phish_then_inject",
        label="Chained: phish then inject",
        description="Phishing harvests a detail that enables auth-code injection.",
        spec_ref=SpecRef(rfc="RFC 9700", section="§4"),
        phase=7,
        applies_to_grants=["authorization_code"],
    ),
]

_BY_ID: Dict[str, RegistryItem] = {i.id: i for i in [*CAPABILITIES, *ATTACKS]}


def get(item_id: str) -> RegistryItem | None:
    return _BY_ID.get(item_id)


def to_catalog_dict() -> Dict[str, Any]:
    """The payload for ``GET /api/catalog``."""
    return {
        "capabilities": [c.to_dict() for c in CAPABILITIES],
        "attacks": [a.to_dict() for a in ATTACKS],
    }
