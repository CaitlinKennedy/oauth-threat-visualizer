import { GLOSSARY, hasGlossary } from "../glossary";

interface Props {
  term: string;
  children?: React.ReactNode;
}

// Renders a term with an accessible tooltip when it is in the glossary,
// otherwise plain text. Keyboard-focusable so the definition is reachable
// without a mouse.
export function GlossaryTooltip({ term, children }: Props) {
  const label = children ?? term;
  if (!hasGlossary(term)) return <>{label}</>;
  const definition = GLOSSARY[term];
  return (
    <span
      className="glossary"
      tabIndex={0}
      role="note"
      aria-label={`${term}: ${definition}`}
      title={definition}
    >
      {label}
      <span className="glossary-tip" aria-hidden="true">
        {definition}
      </span>
    </span>
  );
}
