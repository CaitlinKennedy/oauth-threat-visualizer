"""Collects ordered, correlated :class:`StepEvent` objects into a Trace.

The actors never build a :class:`~otv.contract.Trace` directly; they emit steps
into a shared ``Recorder``, which assigns monotonically increasing ``seq``
values and accumulates the running actor-knowledge ledger. The conductor then
seals the recorder into a finished trace with a verdict.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .contract import (
    Check,
    HttpExchange,
    KnowledgeState,
    ScenarioConfig,
    SpecRef,
    StepEvent,
    Trace,
    Verdict,
)


class Recorder:
    def __init__(self, correlation_id: str, config: ScenarioConfig):
        self.correlation_id = correlation_id
        self.config = config
        self._events: List[StepEvent] = []
        self._seq = 0
        # Running ledger of what each actor holds, so the UI can show cumulative
        # state as well as per-step deltas.
        self._ledger: Dict[str, KnowledgeState] = {}

    def emit(
        self,
        *,
        actor: str,
        on_behalf_of: str,
        phase: str,
        summary: str,
        detail: str,
        outcome: str,
        refs: Optional[List[int]] = None,
        http: Optional[HttpExchange] = None,
        check: Optional[Check] = None,
        knowledge_delta: Optional[Dict[str, KnowledgeState]] = None,
        spec_refs: Optional[List[SpecRef]] = None,
    ) -> int:
        """Record a step and return its assigned ``seq``."""
        self._seq += 1
        delta = knowledge_delta or {}
        self._apply_ledger(delta)
        event = StepEvent(
            seq=self._seq,
            actor=actor,
            on_behalf_of=on_behalf_of,
            phase=phase,
            summary=summary,
            detail=detail,
            outcome=outcome,
            refs=refs or [],
            http=http,
            check=check,
            knowledge_delta=delta,
            spec_refs=spec_refs or [],
        )
        self._events.append(event)
        return self._seq

    @property
    def last_seq(self) -> int:
        return self._seq

    @property
    def events(self) -> List[StepEvent]:
        return list(self._events)

    def _apply_ledger(self, delta: Dict[str, KnowledgeState]) -> None:
        for actor, ks in delta.items():
            current = self._ledger.setdefault(actor, KnowledgeState())
            for item in ks.has:
                if item not in current.has:
                    current.has.append(item)
                if item in current.lacks:
                    current.lacks.remove(item)
            for item in ks.lacks:
                if item not in current.lacks and item not in current.has:
                    current.lacks.append(item)

    def seal(self, verdict: Verdict) -> Trace:
        return Trace(
            correlation_id=self.correlation_id,
            config=self.config,
            verdict=verdict,
            events=self.events,
        )
