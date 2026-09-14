"""The paired-diff engine — the flow-2 vs flow-3 gesture, computed server-side.

``POST /api/run`` with a ``compare`` block names a baseline and a variant that
differ by one toggle (e.g. ``pkce.active`` false → true). This module runs both
and computes where they diverge, so the diff is authoritative and
snapshot-testable on the server rather than reconstructed in the client
(IMPLEMENTATION.md §3).

The two runs are executed **sequentially**. Each :func:`conductor.run` builds its
own :class:`~otv.recorder.Recorder`, and sequential execution keeps the
process-global trace-context ``ContextVar`` safe. (If these were ever
parallelized, each run would need its own ``contextvars.copy_context()``; the
simplest correct choice is not to parallelize.)
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from ..contract import CompareResponse, Divergence, ScenarioConfig, StepEvent, Trace
from . import conductor


def run_compare(
    baseline_config: ScenarioConfig, variant_config: ScenarioConfig
) -> CompareResponse:
    """Run ``baseline`` then ``variant`` and compute their divergences."""
    baseline = conductor.run(baseline_config)  # sequential — see module docstring
    variant = conductor.run(variant_config)
    capability = _differing_capability(baseline_config, variant_config)
    divergences = _divergences(baseline, variant, capability)
    return CompareResponse(baseline=baseline, variant=variant, divergences=divergences)


def _fingerprint(e: StepEvent) -> Tuple:
    """The structural identity of a step, ignoring run-specific random values.

    Two steps with the same fingerprint are "the same step" for diff purposes — so
    a PKCE-on run that merely carries an extra ``code_challenge`` in a request body
    still matches its PKCE-off twin, and the runs are seen to stay identical until
    the step where the outcome (or a check result) actually differs.
    """
    return (
        e.actor,
        e.actor_instance,
        e.phase,
        e.outcome,
        e.summary,
        e.on_behalf_of,
        e.check.name if e.check else None,
        e.check.result if e.check else None,
    )


def _divergences(
    baseline: Trace, variant: Trace, capability: str
) -> List[Divergence]:
    """The first point where the two runs stop being the same flow."""
    b, v = baseline.events, variant.events
    n = min(len(b), len(v))
    for i in range(n):
        if _fingerprint(b[i]) != _fingerprint(v[i]):
            return [_divergence_at(v[i], capability)]
    # Prefixes match but one run has extra trailing steps: they diverge at the
    # first step the shorter run does not have.
    if len(b) != len(v):
        longer = v if len(v) > len(b) else b
        return [_divergence_at(longer[n], capability)]
    return []


def _divergence_at(event: StepEvent, capability: str) -> Divergence:
    reason = event.check.name if event.check is not None else f"{event.actor}:{event.outcome}"
    return Divergence(seq=event.seq, reason=reason, capability=capability or reason)


def _differing_capability(a: ScenarioConfig, b: ScenarioConfig) -> str:
    """The single capability id that differs between the two configs (if any).

    A capability can differ two ways: active in one config and not the other
    (an id-level diff — PKCE, state, DPoP), or active in BOTH with different
    params — same catalog id, different configuration (e.g. ``client_auth``'s
    ``method``: ``client_secret_basic`` vs ``private_key_jwt``). Checking only
    the active-id set misses the second case entirely, which left a param-only
    compare (like the client-auth leak) with no differing id and made the
    divergence's ``capability`` field fall back to a check name instead of a
    real catalog id.
    """
    active_a = set(a.active_capabilities())
    active_b = set(b.active_capabilities())
    diff = sorted(active_a ^ active_b)
    if diff:
        return diff[0]
    for cid in sorted(active_a & active_b):
        if a.capabilities[cid].params != b.capabilities[cid].params:
            return cid
    # Fall back to a differing attack id, else empty (callers guarantee a toggle).
    attack_diff = sorted(set(a.active_attacks()) ^ set(b.active_attacks()))
    return attack_diff[0] if attack_diff else ""
