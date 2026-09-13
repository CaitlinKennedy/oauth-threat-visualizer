import { ACTOR_LABELS, type StepEvent } from "../types/trace";

interface Props {
  events: StepEvent[];
  currentIndex: number;
  onSelect: (index: number) => void;
  // In compare mode, the seq where the two runs diverge — marked clearly so the
  // reader can see exactly where the mitigation changes the outcome.
  divergenceSeq?: number | null;
}

// The step rail (right column): every step as a button, so the whole rail is
// keyboard-navigable and any step can be jumped to directly. Checks surface a
// ✓/✗ line (glyph + text, never color alone) where the protocol decides.
export function Timeline({ events, currentIndex, onSelect, divergenceSeq }: Props) {
  return (
    <div className="card rail-card">
      <div className="rail-head">Steps</div>
      <ol className="rail" aria-label="Flow steps">
        {events.map((e, i) => {
          const current = i === currentIndex;
          const diverges = divergenceSeq != null && e.seq === divergenceSeq;
          return (
            <li key={e.seq}>
              {diverges && (
                <span className="rail-diverge" aria-hidden="true">
                  ⎇ runs diverge here
                </span>
              )}
              <button
                className={`rail-btn ${current ? "rail-current" : ""} ${
                  i < currentIndex ? "rail-past" : ""
                } ${diverges ? "rail-diverge-step" : ""}`}
                aria-current={current ? "step" : undefined}
                aria-label={
                  diverges
                    ? `Step ${e.seq} (runs diverge here): ${e.summary}`
                    : undefined
                }
                onClick={() => onSelect(i)}
              >
                <span className="rail-seq">{e.seq}</span>
                <span className="rail-meta">
                  <span className="rail-actor">{ACTOR_LABELS[e.actor]}</span>
                  <span className="rail-phase">{e.phase}</span>
                </span>
                <span className="rail-summary">{e.summary}</span>
                {e.check && (
                  <span
                    className={`rail-check tc-${e.check.result.toLowerCase()}`}
                    title={`${e.check.name}: ${e.check.result}`}
                  >
                    {e.check.result === "PASS" ? "✓ check" : "✗ check"}
                  </span>
                )}
              </button>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
