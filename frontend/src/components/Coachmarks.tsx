import type { ReactNode } from "react";

interface Props {
  // "1 OF 3" style kicker.
  kicker: string;
  body: ReactNode;
  // Position modifier class: "coach-1" | "coach-2" | "coach-3".
  place: string;
  last?: boolean;
  onNext: () => void;
  onSkip: () => void;
}

// One first-run coachmark tooltip. Three are shown in sequence, one at a time,
// each anchored to the thing it describes. Re-openable from the `?` button.
export function Coachmark({ kicker, body, place, last, onNext, onSkip }: Props) {
  return (
    <div className={`coach ${place}`} role="dialog" aria-label={`Tour: ${kicker}`}>
      <div className="coach-caret" aria-hidden="true" />
      <p className="coach-kicker">{kicker}</p>
      <p className="coach-body">{body}</p>
      <div className="coach-actions">
        {last ? (
          <button className="coach-next" onClick={onSkip}>
            Got it
          </button>
        ) : (
          <>
            <button className="coach-next" onClick={onNext}>
              Next
            </button>
            <button className="coach-skip" onClick={onSkip}>
              Skip
            </button>
          </>
        )}
      </div>
    </div>
  );
}
