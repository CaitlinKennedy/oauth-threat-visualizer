import { ACTOR_LABELS, type StepEvent } from "../types/trace";

interface Props {
  events: StepEvent[];
  currentIndex: number;
  onSelect: (index: number) => void;
}

// A scrubbable list of steps. Each step is a button, so the whole timeline is
// keyboard-navigable and any step can be jumped to directly.
export function Timeline({ events, currentIndex, onSelect }: Props) {
  return (
    <ol className="timeline" aria-label="Flow steps">
      {events.map((e, i) => {
        const current = i === currentIndex;
        return (
          <li key={e.seq} className="timeline-item">
            <button
              className={`timeline-btn ${current ? "timeline-current" : ""} ${
                i < currentIndex ? "timeline-past" : ""
              }`}
              aria-current={current ? "step" : undefined}
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
