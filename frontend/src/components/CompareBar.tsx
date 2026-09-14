import type { CompareResponse, FeatureState } from "../types/trace";

interface Props {
  compare: CompareResponse;
  side: "baseline" | "variant";
  onSetSide: (side: "baseline" | "variant") => void;
  currentSeq: number | null;
  // id -> human label, from the catalog (App.tsx builds this once from
  // GET /api/catalog). Used to turn the divergence's capability id into the
  // words shown on the toggle, rather than hard-coding one capability's name.
  catalogLabels?: Record<string, string>;
}

// The flow-2↔3 diff toggle: the PRIMARY gesture. Flip whichever capability the
// two configs differ on and the two runs stay identical until they diverge at
// one highlighted step. Driven entirely by CompareResponse.divergences plus the
// two configs, so it works for any toggle (PKCE, state, client_auth, DPoP, …)
// rather than assuming PKCE.
export function CompareBar({ compare, side, onSetSide, currentSeq, catalogLabels = {} }: Props) {
  const div = compare.divergences[0] ?? null;
  const divSeq = div?.seq ?? null;
  const reached = divSeq != null && currentSeq != null && currentSeq >= divSeq;

  const baselineWon = compare.baseline.verdict.attacker_got_token;
  const variantWon = compare.variant.verdict.attacker_got_token;
  const shownWon = side === "baseline" ? baselineWon : variantWon;

  const capId = div?.capability || differingCapabilityId(compare) || "";
  const capLabel = catalogLabels[capId] ?? capId ?? "the mitigation";
  const { baseline: baselineText, variant: variantText } = sideLabels(
    compare,
    capId,
    capLabel,
  );
  const toggleLabelId = capId ? `${capId}-toggle-label` : "compare-toggle-label";

  return (
    <section className="compare" aria-label={`${capLabel} comparison`}>
      <span className="compare-label" id={toggleLabelId}>
        Flip {capLabel}
      </span>
      <div className="toggle" role="radiogroup" aria-labelledby={toggleLabelId}>
        <button
          className={`toggle-opt ${side === "baseline" ? "toggle-on" : ""}`}
          role="radio"
          aria-checked={side === "baseline"}
          onClick={() => onSetSide("baseline")}
        >
          {baselineText}
        </button>
        <button
          className={`toggle-opt ${side === "variant" ? "toggle-on" : ""}`}
          role="radio"
          aria-checked={side === "variant"}
          onClick={() => onSetSide("variant")}
        >
          {variantText}
        </button>
      </div>
      <span
        className={`compare-outcome ${shownWon ? "outcome-bad" : "outcome-good"}`}
      >
        <span aria-hidden="true">{shownWon ? "✗ " : "✓ "}</span>
        {shownWon ? "Attacker wins" : "Attacker blocked"}
      </span>
      <span className="compare-hint" aria-hidden="true">
        p flips {capLabel.toLowerCase()}
      </span>

      {div ? (
        <p className="compare-explain">
          Both runs are byte-for-byte the same flow until{" "}
          <strong>step {div.seq}</strong>
          {reached ? " — you are at or past it now" : " — step forward to reach it"}.
          There, <strong>{capLabel}</strong> decides the outcome (
          <code>{div.reason}</code>): with <strong>{baselineText}</strong> the check
          comes out one way; with <strong>{variantText}</strong> it comes out the
          other. Flip the toggle to watch the same step succeed or fail.
        </p>
      ) : (
        <p className="compare-explain">The two runs did not diverge.</p>
      )}
    </section>
  );
}

// Fallback for the (should-not-happen) case where a divergence carries no
// capability id: fall back to whichever capability actually differs between
// the two configs, the same way the backend derives it.
function differingCapabilityId(compare: CompareResponse): string {
  const a = compare.baseline.config.capabilities;
  const b = compare.variant.config.capabilities;
  const ids = new Set([...Object.keys(a), ...Object.keys(b)]);
  for (const id of ids) {
    const av = a[id]?.active ?? false;
    const bv = b[id]?.active ?? false;
    if (av !== bv) return id;
    if (av && bv && JSON.stringify(a[id]?.params ?? {}) !== JSON.stringify(b[id]?.params ?? {})) {
      return id;
    }
  }
  return "";
}

// The words shown on each side of the toggle. Most capabilities are a plain
// on/off switch (PKCE, state, DPoP): "{Label} off" / "{Label} on". A capability
// that stays active on both sides but differs by a param (client_auth's
// `method`) instead shows the differing param value itself, so the toggle
// reads e.g. "client_secret_basic" / "private_key_jwt" rather than a
// meaningless "on"/"on".
function sideLabels(
  compare: CompareResponse,
  capId: string,
  capLabel: string,
): { baseline: string; variant: string } {
  const b: FeatureState | undefined = compare.baseline.config.capabilities[capId];
  const v: FeatureState | undefined = compare.variant.config.capabilities[capId];
  const bActive = b?.active ?? false;
  const vActive = v?.active ?? false;

  if (bActive !== vActive || (!bActive && !vActive)) {
    return { baseline: `${capLabel} off`, variant: `${capLabel} on` };
  }

  const bParams = b?.params ?? {};
  const vParams = v?.params ?? {};
  const keys = new Set([...Object.keys(bParams), ...Object.keys(vParams)]);
  for (const key of keys) {
    if (bParams[key] !== vParams[key]) {
      return { baseline: String(bParams[key] ?? `${capLabel} (baseline)`), variant: String(vParams[key] ?? `${capLabel} (variant)`) };
    }
  }
  return { baseline: `${capLabel} off`, variant: `${capLabel} on` };
}
