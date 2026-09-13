import { ACTOR_LABELS, type Actor, type StepEvent } from "../types/trace";
import { GlossaryTooltip } from "./GlossaryTooltip";

interface Props {
  events: StepEvent[];
  currentIndex: number;
}

// The actor-knowledge ledger: fold every knowledge_delta up to and including the
// current step so the panel shows what each actor holds *right now*.
function ledgerUpTo(events: StepEvent[], index: number) {
  const ledger: Record<string, { has: Set<string>; lacks: Set<string> }> = {};
  for (let i = 0; i <= index && i < events.length; i++) {
    const delta = events[i].knowledge_delta || {};
    for (const [actor, ks] of Object.entries(delta)) {
      if (!ks) continue;
      const slot = (ledger[actor] ??= { has: new Set(), lacks: new Set() });
      for (const item of ks.has) {
        slot.has.add(item);
        slot.lacks.delete(item);
      }
      for (const item of ks.lacks) {
        if (!slot.has.has(item)) slot.lacks.add(item);
      }
    }
  }
  return ledger;
}

const ORDER: Actor[] = ["client", "auth_server", "resource_server", "attacker"];

export function KnowledgePanel({ events, currentIndex }: Props) {
  const ledger = ledgerUpTo(events, currentIndex);
  return (
    <div className="knowledge">
      <h2 className="panel-title">Actor knowledge</h2>
      <p className="panel-hint">What each actor holds at this step.</p>
      <ul className="knowledge-list">
        {ORDER.map((actor) => {
          const slot = ledger[actor];
          const has = slot ? [...slot.has] : [];
          const lacks = slot ? [...slot.lacks] : [];
          return (
            <li key={actor} className="knowledge-actor">
              <span className="knowledge-name">{ACTOR_LABELS[actor]}</span>
              <span className="knowledge-items">
                {has.length === 0 && lacks.length === 0 && (
                  <span className="chip chip-empty">nothing yet</span>
                )}
                {has.map((item) => (
                  <span className="chip chip-has" key={`h-${item}`}>
                    <span aria-hidden="true">＋ </span>
                    <GlossaryTooltip term={item}>{item}</GlossaryTooltip>
                  </span>
                ))}
                {lacks.map((item) => (
                  <span className="chip chip-lacks" key={`l-${item}`}>
                    <span aria-hidden="true">－ </span>lacks{" "}
                    <GlossaryTooltip term={item}>{item}</GlossaryTooltip>
                  </span>
                ))}
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
