import { ACTOR_LABELS, type StepEvent } from "../types/trace";

interface Props {
  events: StepEvent[];
  currentIndex: number;
  onSelect: (index: number) => void;
  // In compare mode, the seq where the two runs diverge — marked clearly so the
  // reader can see exactly where the mitigation changes the outcome.
  divergenceSeq?: number | null;
}

// A scrubbable list of steps. Each step is a button, so the whole timeline is
// keyboard-navigable and any step can be jumped to directly.
export function Timeline({ events, currentIndex, onSelect, divergenceSeq }: Props) {
  return (
    <ol className="timeline" aria-label="Flow steps">
      {events.map((e, i) => {
        const current = i === currentIndex;
        const diverges = divergenceSeq != null && e.seq === divergenceSeq;
        return (
          <li key={e.seq} className="timeline-item">
            {diverges && (
              <span className="timeline-diverge" aria-hidden="true">
                ⎇ runs diverge here
              </span>
            )}
            <button
              className={`timeline-btn ${current ? "timeline-current" : ""} ${
                i < currentIndex ? "timeline-past" : ""
              } ${diverges ? "timeline-diverge-step" : ""}`}
              aria-current={current ? "step" : undefined}
              aria-label={diverges ? `Step ${e.seq} (runs diverge here): ${e.summary}` : undefined}
              onClick={() => onSelect(i)}
            >
              <span className="timeline-seq">{e.seq}</span>
              <span className="timeline-meta">
                <span className="timeline-actor">{ACTOR_LABELS[e.actor]}</span>
                <span className="timeline-phase">{e.phase}</span>
              </span>
              <span className="timeline-summary">{e.summary}</span>
              {e.check && (
                <span
                  className={`timeline-check tc-${e.check.result.toLowerCase()}`}
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
  );
}
