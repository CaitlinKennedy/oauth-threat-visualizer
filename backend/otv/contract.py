"""The frozen trace / event contract.

This module is the single, stable seam between the OAuth actors and the UI.
Every actor emits ``StepEvent`` objects into a ``Recorder``; a run is
materialized into a ``Trace``; the UI is a pure function of that ``Trace``.

The shape defined here is deliberately frozen: ``frontend/src/types/trace.ts``
mirrors it exactly, and ``SCHEMA_VERSION`` plus :func:`validate` guard against
drift. Live runs and committed fixtures emit the identical shape, so the UI
cannot tell them apart.

Only additive, backwards-compatible growth is intended over time. If the shape
must change incompatibly, bump ``SCHEMA_VERSION``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

# Bump only on an incompatible change to the shape below.
SCHEMA_VERSION = "1.0"

# --- Enumerations (kept as frozen tuples so the validator and the TS mirror
# --- can be checked against a single source of truth). ---------------------

ACTORS = ("client", "auth_server", "resource_server", "attacker")
PHASES = ("authorize", "redirect", "token", "resource", "introspect")
OUTCOMES = ("ok", "blocked", "attack_success", "attack_blocked")
CHECK_RESULTS = ("PASS", "FAIL")
GRANTS = ("authorization_code", "client_credentials", "jwt_bearer")


class ContractError(ValueError):
    """Raised when a trace or event does not satisfy the frozen contract."""


# --- Leaf structures -------------------------------------------------------


@dataclass
class SpecRef:
    """A pointer to the exact clause of a specification that governs a step."""

    rfc: str
    section: str


@dataclass
class HttpMessage:
    method: Optional[str] = None
    url: Optional[str] = None
    status: Optional[int] = None
    headers: Dict[str, Any] = field(default_factory=dict)
    body: Any = None


@dataclass
class HttpExchange:
    """An exact request/response pair; ``highlight`` flags the decisive field(s)."""

    request: HttpMessage
    response: HttpMessage
    highlight: List[str] = field(default_factory=list)


@dataclass
class Check:
    """A first-class mitigation checkpoint: expected vs. actual, PASS|FAIL.

    Present only on events that enforce a security-relevant check. The
    ``spec_ref`` names the clause that *mandates* the check.
    """

    name: str
    rule: str
    result: str  # one of CHECK_RESULTS
    spec_ref: SpecRef
    expected: Optional[str] = None
    actual: Optional[str] = None


@dataclass
class KnowledgeState:
    """What a single actor holds (``has``) and does not hold (``lacks``)."""

    has: List[str] = field(default_factory=list)
    lacks: List[str] = field(default_factory=list)


# --- Event -----------------------------------------------------------------


@dataclass
class StepEvent:
    seq: int
    actor: str  # one of ACTORS
    on_behalf_of: str  # whose intent this serves; superset of a user|attacker lane
    phase: str  # one of PHASES
    summary: str
    detail: str
    outcome: str  # one of OUTCOMES
    refs: List[int] = field(default_factory=list)
    http: Optional[HttpExchange] = None
    check: Optional[Check] = None
    # actor name -> KnowledgeState delta after this step
    knowledge_delta: Dict[str, KnowledgeState] = field(default_factory=dict)
    spec_refs: List[SpecRef] = field(default_factory=list)


# --- Run-level structures --------------------------------------------------


@dataclass
class FeatureState:
    """The on-the-wire state of one capability or attack.

    Capabilities and attacks are carried as OPEN id-keyed maps of these state
    objects (never bare booleans, never fixed named fields), so adding a feature
    in a later phase is a new catalog/registry entry — the wire schema is frozen.
    """

    active: bool = False
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScenarioConfig:
    grant: str  # one of GRANTS
    # id -> FeatureState. Only the ids the caller sets need appear; catalogued
    # ids the caller omits default from the registry.
    capabilities: Dict[str, FeatureState] = field(default_factory=dict)
    attacks: Dict[str, FeatureState] = field(default_factory=dict)

    def active_capabilities(self) -> List[str]:
        return [cid for cid, st in self.capabilities.items() if st.active]

    def active_attacks(self) -> List[str]:
        return [aid for aid, st in self.attacks.items() if st.active]


@dataclass
class Verdict:
    """The one-sentence answer, plus the machine-readable facts behind it."""

    attacker_got_token: bool
    user_got_token: bool
    user_accessed_resource: bool
    one_line: str
    blocked_at_seq: Optional[int] = None
    responsible_capability: Optional[str] = None


@dataclass
class Trace:
    correlation_id: str
    config: ScenarioConfig
    verdict: Verdict
    events: List[StepEvent] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    # Reserved for Phase 4 chained attacks (linked sub-traces): both null for a
    # standalone run. Present in v1.0 so chaining needs no schema change.
    parent_id: Optional[str] = None
    chain_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to plain JSON-able dicts (dropping ``None`` optionals)."""
        d = _prune(asdict(self))
        # The reserved envelope fields are always present on the wire (null when
        # unused), so chained-attack consumers can rely on their existence.
        d["parent_id"] = self.parent_id
        d["chain_id"] = self.chain_id
        return d


# --- Serialization helpers -------------------------------------------------


def _prune(value: Any) -> Any:
    """Recursively drop ``None`` values from dicts so optional fields are omitted.

    Empty lists/dicts are preserved (they are meaningful, e.g. ``refs: []``).
    """
    if isinstance(value, dict):
        return {k: _prune(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_prune(v) for v in value]
    return value


def _spec_ref_from_dict(d: Dict[str, Any]) -> SpecRef:
    return SpecRef(rfc=d["rfc"], section=d["section"])


def _http_message_from_dict(d: Dict[str, Any]) -> HttpMessage:
    return HttpMessage(
        method=d.get("method"),
        url=d.get("url"),
        status=d.get("status"),
        headers=d.get("headers", {}) or {},
        body=d.get("body"),
    )


def feature_map_from_dict(raw: Any) -> Dict[str, FeatureState]:
    """Parse an id-keyed map of feature states, tolerating a bare-bool shorthand.

    ``{"pkce": {"active": true, "params": {...}}}`` is canonical;
    ``{"pkce": true}`` is accepted and coerced for convenience.
    """
    out: Dict[str, FeatureState] = {}
    for fid, st in (raw or {}).items():
        if isinstance(st, bool):
            out[fid] = FeatureState(active=st)
        elif isinstance(st, dict):
            out[fid] = FeatureState(
                active=bool(st.get("active", False)),
                params=st.get("params", {}) or {},
            )
        else:
            raise ContractError(
                f"feature {fid!r} state must be an object or bool, got {type(st).__name__}"
            )
    return out


def trace_from_dict(d: Dict[str, Any]) -> Trace:
    """Rehydrate a :class:`Trace` from plain dicts (e.g. a committed fixture)."""
    config = ScenarioConfig(
        grant=d["config"]["grant"],
        capabilities=feature_map_from_dict(d["config"].get("capabilities", {})),
        attacks=feature_map_from_dict(d["config"].get("attacks", {})),
    )
    v = d["verdict"]
    verdict = Verdict(
        attacker_got_token=v["attacker_got_token"],
        user_got_token=v["user_got_token"],
        user_accessed_resource=v["user_accessed_resource"],
        one_line=v["one_line"],
        blocked_at_seq=v.get("blocked_at_seq"),
        responsible_capability=v.get("responsible_capability"),
    )
    events: List[StepEvent] = []
    for e in d.get("events", []):
        http = None
        if e.get("http") is not None:
            http = HttpExchange(
                request=_http_message_from_dict(e["http"].get("request", {})),
                response=_http_message_from_dict(e["http"].get("response", {})),
                highlight=e["http"].get("highlight", []) or [],
            )
        check = None
        if e.get("check") is not None:
            c = e["check"]
            check = Check(
                name=c["name"],
                rule=c["rule"],
                result=c["result"],
                spec_ref=_spec_ref_from_dict(c["spec_ref"]),
                expected=c.get("expected"),
                actual=c.get("actual"),
            )
        knowledge_delta = {
            actor: KnowledgeState(
                has=ks.get("has", []) or [], lacks=ks.get("lacks", []) or []
            )
            for actor, ks in (e.get("knowledge_delta", {}) or {}).items()
        }
        events.append(
            StepEvent(
                seq=e["seq"],
                actor=e["actor"],
                on_behalf_of=e["on_behalf_of"],
                phase=e["phase"],
                summary=e["summary"],
                detail=e["detail"],
                outcome=e["outcome"],
                refs=e.get("refs", []) or [],
                http=http,
                check=check,
                knowledge_delta=knowledge_delta,
                spec_refs=[_spec_ref_from_dict(s) for s in e.get("spec_refs", []) or []],
            )
        )
    return Trace(
        correlation_id=d["correlation_id"],
        config=config,
        verdict=verdict,
        events=events,
        schema_version=d.get("schema_version", SCHEMA_VERSION),
        parent_id=d.get("parent_id"),
        chain_id=d.get("chain_id"),
    )


# --- Validator -------------------------------------------------------------


def validate(trace: Trace | Dict[str, Any]) -> None:
    """Validate a trace against the frozen contract.

    Accepts either a :class:`Trace` instance or its dict form. Raises
    :class:`ContractError` on the first violation with an explanatory message.
    This is the guard used by both the API and the test suite.
    """
    d = trace.to_dict() if isinstance(trace, Trace) else _prune(trace)

    if d.get("schema_version") != SCHEMA_VERSION:
        raise ContractError(
            f"schema_version must be {SCHEMA_VERSION!r}, got {d.get('schema_version')!r}"
        )

    if not isinstance(d.get("correlation_id"), str) or not d["correlation_id"]:
        raise ContractError("correlation_id must be a non-empty string")

    _validate_config(d.get("config"))
    _validate_verdict(d.get("verdict"))

    events = d.get("events")
    if not isinstance(events, list) or not events:
        raise ContractError("events must be a non-empty list")

    seen_seqs: set[int] = set()
    prev_seq: Optional[int] = None
    for i, e in enumerate(events):
        _validate_event(e, index=i)
        seq = e["seq"]
        if seq in seen_seqs:
            raise ContractError(f"duplicate seq {seq}")
        seen_seqs.add(seq)
        if prev_seq is not None and seq <= prev_seq:
            raise ContractError(
                f"events must be strictly increasing by seq: {seq} follows {prev_seq}"
            )
        prev_seq = seq

    # refs must point at earlier, existing events.
    for e in events:
        for r in e.get("refs", []):
            if r not in seen_seqs:
                raise ContractError(f"seq {e['seq']} refs unknown seq {r}")
            if r >= e["seq"]:
                raise ContractError(
                    f"seq {e['seq']} refs {r}, which is not an earlier event"
                )

    # blocked_at_seq, when present, must name a real event.
    blocked_at = d["verdict"].get("blocked_at_seq")
    if blocked_at is not None and blocked_at not in seen_seqs:
        raise ContractError(f"verdict.blocked_at_seq {blocked_at} names no event")


def _validate_config(config: Any) -> None:
    if not isinstance(config, dict):
        raise ContractError("config must be an object")
    if config.get("grant") not in GRANTS:
        raise ContractError(f"config.grant must be one of {GRANTS}, got {config.get('grant')!r}")
    _validate_feature_map(config.get("capabilities", {}), "config.capabilities")
    _validate_feature_map(config.get("attacks", {}), "config.attacks")


def _validate_feature_map(m: Any, where: str) -> None:
    """An open id-keyed map of ``{active: bool, params?: object}`` state objects."""
    if not isinstance(m, dict):
        raise ContractError(f"{where} must be an id-keyed object")
    for fid, st in m.items():
        if not isinstance(fid, str) or not fid:
            raise ContractError(f"{where} has a non-string id")
        if not isinstance(st, dict):
            raise ContractError(f"{where}[{fid}] must be a state object")
        if not isinstance(st.get("active"), bool):
            raise ContractError(f"{where}[{fid}].active must be a bool")
        if "params" in st and not isinstance(st["params"], dict):
            raise ContractError(f"{where}[{fid}].params must be an object")


def _validate_verdict(verdict: Any) -> None:
    if not isinstance(verdict, dict):
        raise ContractError("verdict must be an object")
    for key in ("attacker_got_token", "user_got_token", "user_accessed_resource"):
        if not isinstance(verdict.get(key), bool):
            raise ContractError(f"verdict.{key} must be a bool")
    if not isinstance(verdict.get("one_line"), str) or not verdict["one_line"]:
        raise ContractError("verdict.one_line must be a non-empty string")


def _validate_event(e: Any, index: int) -> None:
    where = f"events[{index}]"
    if not isinstance(e, dict):
        raise ContractError(f"{where} must be an object")
    if not isinstance(e.get("seq"), int):
        raise ContractError(f"{where}.seq must be an int")
    if e.get("actor") not in ACTORS:
        raise ContractError(f"{where}.actor must be one of {ACTORS}, got {e.get('actor')!r}")
    if not isinstance(e.get("on_behalf_of"), str) or not e["on_behalf_of"]:
        raise ContractError(f"{where}.on_behalf_of must be a non-empty string")
    if e.get("phase") not in PHASES:
        raise ContractError(f"{where}.phase must be one of {PHASES}, got {e.get('phase')!r}")
    if e.get("outcome") not in OUTCOMES:
        raise ContractError(f"{where}.outcome must be one of {OUTCOMES}, got {e.get('outcome')!r}")
    for key in ("summary", "detail"):
        if not isinstance(e.get(key), str) or not e[key]:
            raise ContractError(f"{where}.{key} must be a non-empty string")
    if not isinstance(e.get("refs", []), list) or not all(
        isinstance(r, int) for r in e.get("refs", [])
    ):
        raise ContractError(f"{where}.refs must be a list of ints")

    if e.get("http") is not None:
        _validate_http(e["http"], where)
    if e.get("check") is not None:
        _validate_check(e["check"], where)
    _validate_knowledge_delta(e.get("knowledge_delta", {}), where)
    for j, s in enumerate(e.get("spec_refs", [])):
        _validate_spec_ref(s, f"{where}.spec_refs[{j}]")


def _validate_http(http: Any, where: str) -> None:
    if not isinstance(http, dict):
        raise ContractError(f"{where}.http must be an object")
    for side in ("request", "response"):
        msg = http.get(side)
        if not isinstance(msg, dict):
            raise ContractError(f"{where}.http.{side} must be an object")
    if not isinstance(http.get("highlight", []), list):
        raise ContractError(f"{where}.http.highlight must be a list")


def _validate_check(check: Any, where: str) -> None:
    if not isinstance(check, dict):
        raise ContractError(f"{where}.check must be an object")
    for key in ("name", "rule"):
        if not isinstance(check.get(key), str) or not check[key]:
            raise ContractError(f"{where}.check.{key} must be a non-empty string")
    if check.get("result") not in CHECK_RESULTS:
        raise ContractError(
            f"{where}.check.result must be one of {CHECK_RESULTS}, got {check.get('result')!r}"
        )
    _validate_spec_ref(check.get("spec_ref"), f"{where}.check.spec_ref")


def _validate_knowledge_delta(delta: Any, where: str) -> None:
    if not isinstance(delta, dict):
        raise ContractError(f"{where}.knowledge_delta must be an object")
    for actor, ks in delta.items():
        if actor not in ACTORS:
            raise ContractError(
                f"{where}.knowledge_delta has unknown actor {actor!r}"
            )
        if not isinstance(ks, dict):
            raise ContractError(f"{where}.knowledge_delta[{actor}] must be an object")
        for key in ("has", "lacks"):
            if not isinstance(ks.get(key, []), list):
                raise ContractError(
                    f"{where}.knowledge_delta[{actor}].{key} must be a list"
                )


def _validate_spec_ref(s: Any, where: str) -> None:
    if not isinstance(s, dict):
        raise ContractError(f"{where} must be an object")
    for key in ("rfc", "section"):
        if not isinstance(s.get(key), str) or not s[key]:
            raise ContractError(f"{where}.{key} must be a non-empty string")
