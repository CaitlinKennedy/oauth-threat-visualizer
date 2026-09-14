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
# ``partial`` marks a step that neither fully succeeds nor is fully blocked — e.g.
# a replayed code that PKCE downgrades to a partial win (DESIGN.md §6).
OUTCOMES = ("ok", "blocked", "attack_success", "attack_blocked", "partial")
CHECK_RESULTS = ("PASS", "FAIL")
# ``implicit`` is a recognized grant with no runner in this build: a run that
# requests it is refused outright rather than silently handled by another runner.
GRANTS = ("authorization_code", "client_credentials", "jwt_bearer", "implicit")


def enum_manifest() -> Dict[str, Any]:
    """The frozen enum tuples + ``SCHEMA_VERSION`` as a plain, JSON-able dict.

    Emitted to ``contract_enums.json`` (a committed, generated artifact) so a test
    can assert this Python source and the ``frontend/src/types/trace.ts`` mirror
    never drift apart — including the duplicated ``SCHEMA_VERSION``.
    """
    return {
        "SCHEMA_VERSION": SCHEMA_VERSION,
        "ACTORS": list(ACTORS),
        "PHASES": list(PHASES),
        "OUTCOMES": list(OUTCOMES),
        "CHECK_RESULTS": list(CHECK_RESULTS),
        "GRANTS": list(GRANTS),
    }


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
    """An exact request/response pair; ``highlight`` flags the decisive field(s).

    Each ``highlight`` entry is a **dotted path** that disambiguates *where* the
    decisive field lives, so the UI can flag the right one when the same key name
    appears on both sides of the exchange (e.g. ``client_secret`` in a request
    body vs. a response body). The convention is::

        <side>.<section>.<key>

    where ``side`` is ``request`` or ``response`` and ``section`` is one of
    ``headers``, ``body``, or ``query`` — for example
    ``request.headers.Authorization``, ``request.body.client_secret``,
    ``request.query.state``. Consumers that don't understand the path can still
    fall back to matching on the trailing ``<key>`` segment.
    """

    request: HttpMessage
    response: HttpMessage
    highlight: List[str] = field(default_factory=list)
    # Explicit message direction so the diagram is a pure function of the trace
    # (no hostname string-matching in the UI). Each is one of ACTORS, or None for
    # an actor-internal step with no cross-actor edge. The ``*_instance`` fields
    # disambiguate two instances of one role (e.g. a mix-up scenario's two auth
    # servers); None for single-instance runs.
    source_actor: Optional[str] = None
    target_actor: Optional[str] = None
    source_instance: Optional[str] = None
    target_instance: Optional[str] = None


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
    # Distinguishes two instances of the *same* role in one run (e.g. an "honest"
    # vs. a "rogue" authorization server in a mix-up scenario) without growing the
    # four-role ACTORS enum. ``None`` when the run has a single instance per role.
    actor_instance: Optional[str] = None
    http: Optional[HttpExchange] = None
    check: Optional[Check] = None
    # actor name -> KnowledgeState delta after this step. Keys may be a bare actor
    # ("attacker") or an instance-qualified "actor#instance" (e.g.
    # "auth_server#rogue"); the actor part must be in ACTORS.
    knowledge_delta: Dict[str, KnowledgeState] = field(default_factory=dict)
    spec_refs: List[SpecRef] = field(default_factory=list)


# --- Run-level structures --------------------------------------------------


@dataclass
class FeatureState:
    """The on-the-wire state of one capability or attack.

    Capabilities and attacks are carried as OPEN id-keyed maps of these state
    objects (never bare booleans, never fixed named fields), so adding a feature
    is a new catalog/registry entry — the wire schema is frozen.
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
    # All capabilities that contributed to blocking the attack, in order, with
    # ``responsible_capability`` as the first/primary blocker. Multiple bindings
    # can compose (e.g. PKCE + state); the plural field carries the full set while
    # the singular stays the headline. Empty when nothing blocked.
    responsible_capabilities: List[str] = field(default_factory=list)


@dataclass
class ChainBlock:
    """Where in a chained attack the block occurred (a specific sub-trace step)."""

    trace_id: str
    seq: int


@dataclass
class ChainVerdict:
    """Roll-up verdict across the linked sub-traces of one chained attack.

    Carried on the terminal sub-trace of a chain (``chain_verdict``); each stage
    still has its own per-trace :class:`Verdict`.
    """

    attacker_got_token: bool
    responsible_capabilities: List[str] = field(default_factory=list)
    blocked_at: Optional[ChainBlock] = None


@dataclass
class Trace:
    correlation_id: str
    config: ScenarioConfig
    verdict: Verdict
    events: List[StepEvent] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    # Reserved for chained attacks (linked sub-traces): both null for a
    # standalone run. Present in v1.0 so chaining needs no schema change.
    parent_id: Optional[str] = None
    chain_id: Optional[str] = None
    # Set only on the terminal sub-trace of a chain: the roll-up across all
    # stages. ``None`` for a standalone run.
    chain_verdict: Optional[ChainVerdict] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to plain JSON-able dicts (dropping ``None`` optionals)."""
        d = _prune(asdict(self))
        # The reserved envelope fields are always present on the wire (null when
        # unused), so chained-attack consumers can rely on their existence.
        d["parent_id"] = self.parent_id
        d["chain_id"] = self.chain_id
        return d


# --- Compare / diff response (the flow-2 vs flow-3 gesture) -----------------
# The SHAPE is frozen here in v1.0; the compare *logic* (running a baseline and a
# variant and computing where they diverge) lives in ``otv.engine.compare``.
# Defining the shape in the contract keeps the wire stable across changes there.


@dataclass
class Divergence:
    """One point where a variant run diverges from its baseline."""

    seq: int
    reason: str
    capability: str


@dataclass
class CompareResponse:
    """The response to a paired ``compare`` run: two traces + their divergences.

    ``divergences`` is a LIST (a single toggle can differ at more than one step,
    e.g. a check *and* a downstream outcome). ``divergence`` is a convenience
    alias for the first entry.
    """

    baseline: Trace
    variant: Trace
    divergences: List[Divergence] = field(default_factory=list)
    mode: str = "compare"

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "mode": self.mode,
            "baseline": self.baseline.to_dict(),
            "variant": self.variant.to_dict(),
            "divergences": [_prune(asdict(dv)) for dv in self.divergences],
        }
        if self.divergences:
            d["divergence"] = _prune(asdict(self.divergences[0]))
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
        responsible_capabilities=v.get("responsible_capabilities", []) or [],
    )
    events: List[StepEvent] = []
    for e in d.get("events", []):
        http = None
        if e.get("http") is not None:
            http = HttpExchange(
                request=_http_message_from_dict(e["http"].get("request", {})),
                response=_http_message_from_dict(e["http"].get("response", {})),
                highlight=e["http"].get("highlight", []) or [],
                source_actor=e["http"].get("source_actor"),
                target_actor=e["http"].get("target_actor"),
                source_instance=e["http"].get("source_instance"),
                target_instance=e["http"].get("target_instance"),
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
                actor_instance=e.get("actor_instance"),
                http=http,
                check=check,
                knowledge_delta=knowledge_delta,
                spec_refs=[_spec_ref_from_dict(s) for s in e.get("spec_refs", []) or []],
            )
        )
    chain_verdict = None
    cv = d.get("chain_verdict")
    if cv is not None:
        blocked_at = None
        if cv.get("blocked_at") is not None:
            blocked_at = ChainBlock(
                trace_id=cv["blocked_at"]["trace_id"], seq=cv["blocked_at"]["seq"]
            )
        chain_verdict = ChainVerdict(
            attacker_got_token=cv["attacker_got_token"],
            responsible_capabilities=cv.get("responsible_capabilities", []) or [],
            blocked_at=blocked_at,
        )
    return Trace(
        correlation_id=d["correlation_id"],
        config=config,
        verdict=verdict,
        events=events,
        schema_version=d.get("schema_version", SCHEMA_VERSION),
        parent_id=d.get("parent_id"),
        chain_id=d.get("chain_id"),
        chain_verdict=chain_verdict,
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

    if d.get("chain_verdict") is not None:
        _validate_chain_verdict(d["chain_verdict"])


def _validate_chain_verdict(cv: Any) -> None:
    if not isinstance(cv, dict):
        raise ContractError("chain_verdict must be an object")
    if not isinstance(cv.get("attacker_got_token"), bool):
        raise ContractError("chain_verdict.attacker_got_token must be a bool")
    caps = cv.get("responsible_capabilities", [])
    if not isinstance(caps, list) or not all(isinstance(c, str) for c in caps):
        raise ContractError(
            "chain_verdict.responsible_capabilities must be a list of strings"
        )
    ba = cv.get("blocked_at")
    if ba is not None:
        if not isinstance(ba, dict):
            raise ContractError("chain_verdict.blocked_at must be an object")
        if not isinstance(ba.get("trace_id"), str) or not ba["trace_id"]:
            raise ContractError("chain_verdict.blocked_at.trace_id must be a non-empty string")
        if not isinstance(ba.get("seq"), int):
            raise ContractError("chain_verdict.blocked_at.seq must be an int")


def validate_compare_response(resp: "CompareResponse | Dict[str, Any]") -> None:
    """Validate a paired compare/diff response against the frozen shape.

    Checks the ``mode`` marker, validates both sub-traces with :func:`validate`,
    and confirms ``divergences`` is a well-formed list (with the optional
    ``divergence`` convenience alias matching the first entry when present).
    """
    d = resp.to_dict() if isinstance(resp, CompareResponse) else _prune(resp)
    if d.get("mode") != "compare":
        raise ContractError(f"compare response.mode must be 'compare', got {d.get('mode')!r}")
    for side in ("baseline", "variant"):
        if side not in d:
            raise ContractError(f"compare response is missing {side!r}")
        validate(d[side])
    divergences = d.get("divergences")
    if not isinstance(divergences, list):
        raise ContractError("compare response.divergences must be a list")
    for i, dv in enumerate(divergences):
        _validate_divergence(dv, f"divergences[{i}]")
    if d.get("divergence") is not None:
        _validate_divergence(d["divergence"], "divergence")


def _validate_divergence(dv: Any, where: str) -> None:
    if not isinstance(dv, dict):
        raise ContractError(f"{where} must be an object")
    if not isinstance(dv.get("seq"), int):
        raise ContractError(f"{where}.seq must be an int")
    for key in ("reason", "capability"):
        if not isinstance(dv.get(key), str) or not dv[key]:
            raise ContractError(f"{where}.{key} must be a non-empty string")


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
    caps = verdict.get("responsible_capabilities", [])
    if not isinstance(caps, list) or not all(isinstance(c, str) for c in caps):
        raise ContractError("verdict.responsible_capabilities must be a list of strings")


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
    if e.get("actor_instance") is not None and not isinstance(e["actor_instance"], str):
        raise ContractError(f"{where}.actor_instance must be a string when present")

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
    highlight = http.get("highlight", [])
    if not isinstance(highlight, list) or not all(isinstance(h, str) for h in highlight):
        raise ContractError(f"{where}.http.highlight must be a list of strings")
    for side in ("source_actor", "target_actor"):
        val = http.get(side)
        if val is not None and val not in ACTORS:
            raise ContractError(
                f"{where}.http.{side} must be one of {ACTORS} when present, got {val!r}"
            )
    for side in ("source_instance", "target_instance"):
        val = http.get(side)
        if val is not None and not isinstance(val, str):
            raise ContractError(f"{where}.http.{side} must be a string when present")


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


def _actor_base(key: str) -> str:
    """The actor part of a knowledge-ledger key, which may be ``actor#instance``."""
    return key.split("#", 1)[0]


def _validate_knowledge_delta(delta: Any, where: str) -> None:
    if not isinstance(delta, dict):
        raise ContractError(f"{where}.knowledge_delta must be an object")
    for actor, ks in delta.items():
        # A ledger key is either a bare actor ("attacker") or an instance-qualified
        # "actor#instance" (e.g. "auth_server#rogue"); the actor part must be known.
        if _actor_base(actor) not in ACTORS:
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
