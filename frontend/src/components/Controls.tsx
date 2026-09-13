interface Props {
  total: number;
  currentIndex: number;
  playing: boolean;
  onPrev: () => void;
  onNext: () => void;
  onTogglePlay: () => void;
  onRestart: () => void;
  onScrub: (index: number) => void;
}

// Step (Prev/Next), one-click "video" play/pause, restart, and a scrub slider.
// Keyboard stepping is handled globally in App; these are the on-screen controls.
export function Controls({
  total,
  currentIndex,
  playing,
  onPrev,
  onNext,
  onTogglePlay,
  onRestart,
  onScrub,
}: Props) {
  const atStart = currentIndex <= 0;
  const atEnd = currentIndex >= total - 1;
  return (
    <div className="controls">
      <div className="controls-buttons">
        <button onClick={onRestart} aria-label="Restart from first step">
          ⏮ Restart
        </button>
        <button onClick={onPrev} disabled={atStart} aria-label="Previous step">
          ◀ Prev
        </button>
        <button
          className="controls-play"
          onClick={onTogglePlay}
          aria-pressed={playing}
          aria-label={playing ? "Pause auto-play" : "Play as video"}
        >
          {playing ? "⏸ Pause" : "▶ Play"}
        </button>
        <button onClick={onNext} disabled={atEnd} aria-label="Next step">
          Next ▶
        </button>
      </div>
      <div className="controls-scrub">
        <label htmlFor="scrub" className="sr-only">
          Scrub to step
        </label>
        <input
          id="scrub"
          type="range"
          min={0}
          max={Math.max(0, total - 1)}
          value={currentIndex}
          onChange={(e) => onScrub(Number(e.target.value))}
          aria-valuetext={`Step ${currentIndex + 1} of ${total}`}
        />
        <span className="controls-count">
          Step {currentIndex + 1} / {total}
        </span>
      </div>
    </div>
  );
}
