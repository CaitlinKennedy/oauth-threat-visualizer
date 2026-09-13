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

// The playback row that lives inside the diagram card: restart, step, one-click
// "video" play/pause, and a scrub slider. Global keyboard stepping is handled in
// App; these are the on-screen controls.
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
    <div className="playback">
      <button className="pb-btn" onClick={onRestart} aria-label="Restart from first step">
        ⏮
      </button>
      <button
        className="pb-btn"
        onClick={onPrev}
        disabled={atStart}
        aria-label="Previous step"
      >
        ◀ Prev
      </button>
      <button
        className="pb-play"
        onClick={onTogglePlay}
        aria-pressed={playing}
        aria-label={playing ? "Pause auto-play" : "Play as video"}
      >
        {playing ? "⏸ Pause" : "▶ Play"}
      </button>
      <button className="pb-btn" onClick={onNext} disabled={atEnd} aria-label="Next step">
        Next ▶
      </button>
      <label htmlFor="scrub" className="sr-only">
        Scrub to step
      </label>
      <input
        id="scrub"
        className="pb-scrub"
        type="range"
        min={0}
        max={Math.max(0, total - 1)}
        value={currentIndex}
        onChange={(e) => onScrub(Number(e.target.value))}
        aria-valuetext={`Step ${currentIndex + 1} of ${total}`}
      />
      <span className="pb-hint" aria-hidden="true">
        ← → step · space play
      </span>
    </div>
  );
}
