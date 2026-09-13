import type { CompareResponse } from "../types/trace";

interface Props {
  compare: CompareResponse;
  side: "baseline" | "variant";
  onSetSide: (side: "baseline" | "variant") => void;
  currentSeq: number | null;
}

// The flow-2↔3 diff toggle: the PRIMARY gesture (DESIGN.md §8). Flip PKCE and the
// two runs stay identical until they diverge at one highlighted step. Driven
// entirely by CompareResponse.divergences, so it is a pure function of the trace.
export function CompareBar({ compare, side, onSetSide, currentSeq }: Props) {
  const div = compare.divergences[0] ?? null;
  const divSeq = div?.seq ?? null;
  const reached = divSeq != null && currentSeq != null && currentSeq >= divSeq;

  const baselineWon = compare.baseline.verdict.attacker_got_token;
  const variantWon = compare.variant.verdict.attacker_got_token;
  const cap = div?.capability ?? "the mitigation";

  return (
    <section className="compare" aria-label="PKCE comparison">
      <div className="compare-controls">
        <span className="compare-label" id="pkce-toggle-label">
          Flip PKCE
        </span>
        <div
          className="toggle"
          role="radiogroup"
          aria-labelledby="pkce-toggle-label"
        >
          <button
            className={`toggle-opt ${side === "baseline" ? "toggle-on" : ""}`}
            role="radio"
            aria-checked={side === "baseline"}
            onClick={() => onSetSide("baseline")}
          >
            PKCE off
          </button>
          <button
            className={`toggle-opt ${side === "variant" ? "toggle-on" : ""}`}
            role="radio"
            aria-checked={side === "variant"}
            onClick={() => onSetSide("variant")}
          >
            PKCE on
          </button>
        </div>
        <span className={`compare-outcome ${(side === "baseline" ? baselineWon : variantWon) ? "outcome-bad" : "outcome-good"}`}>
          <span aria-hidden="true">
            {(side === "baseline" ? baselineWon : variantWon) ? "✗ " : "✓ "}
          </span>
          {side === "baseline"
            ? baselineWon
              ? "Attacker wins"
              : "Attacker blocked"
            : variantWon
              ? "Attacker wins"
              : "Attacker blocked"}
        </span>
      </div>

      {div ? (
        <p className="compare-explain">
          Both runs are byte-for-byte the same flow until{" "}
          <strong>step {div.seq}</strong>
          {reached ? " — you are at or past it now" : " — step forward to reach it"}.
          There, <strong>{cap}</strong> decides the outcome (
          <code>{div.reason}</code>): with PKCE off the token endpoint has nothing
          to check, with PKCE on the verifier does not match. Flip the toggle to
          watch the same step succeed or fail.
        </p>
      ) : (
        <p className="compare-explain">The two runs did not diverge.</p>
      )}
    </section>
  );
}
