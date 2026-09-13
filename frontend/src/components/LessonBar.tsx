interface Lesson {
  name: string;
  blurb: string;
}

interface Props {
  lessons: Lesson[];
  current: number;
  onSelect: (index: number) => void;
  onNext: () => void;
}

// The three-lesson training progression along the bottom of the run view. Each
// dot is clickable; selecting a lesson resets the step index and pauses (handled
// in App). The primary button advances to the next lesson, or reads "Course
// complete" (disabled) on the last.
export function LessonBar({ lessons, current, onSelect, onNext }: Props) {
  const atEnd = current >= lessons.length - 1;
  const lesson = lessons[current];
  if (!lesson) return null;
  return (
    <div className="lessonbar">
      <span className="lesson-dots" role="tablist" aria-label="Lessons">
        {lessons.map((l, i) => (
          <button
            key={l.name}
            className={`lesson-dot ${
              i === current ? "current" : i < current ? "done" : ""
            }`}
            title={l.name}
            aria-label={`Lesson ${i + 1}: ${l.name}`}
            aria-current={i === current ? "true" : undefined}
            onClick={() => onSelect(i)}
          />
        ))}
      </span>
      <span className="lesson-name">
        <strong>
          Lesson {current + 1} of {lessons.length}
        </strong>{" "}
        · {lesson.name}
      </span>
      <span className="lesson-blurb">{lesson.blurb}</span>
      <button className="lesson-next" onClick={onNext} disabled={atEnd}>
        {atEnd ? "Course complete" : `Next: ${lessons[current + 1].name} →`}
      </button>
    </div>
  );
}
