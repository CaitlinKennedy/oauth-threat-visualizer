import { ACTOR_LABELS, type Actor, type StepEvent } from "../types/trace";
import { GlossaryTooltip } from "./GlossaryTooltip";

interface Props {
  events: StepEvent[];
  currentIndex: number;
  stepNo: number;
}

// The actor-knowledge ledger: fold every knowledge_delta up to and including the
// current step so the grid shows what each actor holds *right now*. Kept as an
// exported helper because the "Who holds what" tab of the step card is a pure
// projection of the same trace.
export function ledgerUpTo(events: StepEvent[], index: number) {
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

// The four-cell "Who holds what" grid — one cell per actor of has/lacks chips.
// Keys in knowledge_delta may be instance-qualified ("auth_server#rogue"); we
// merge on the bare actor part so a single-instance run reads cleanly.
export function KnowledgeGrid({ events, currentIndex, stepNo }: Props) {
  const ledger = ledgerUpTo(events, currentIndex);
  const forActor = (actor: Actor) => {
    const merged = { has: new Set<string>(), lacks: new Set<string>() };
    for (const [key, slot] of Object.entries(ledger)) {
      if (key.split("#")[0] !== actor) continue;
      slot.has.forEach((i) => merged.has.add(i));
      slot.lacks.forEach((i) => {
        if (!merged.has.has(i)) merged.lacks.add(i);
      });
    }
    return merged;
  };

  return (
    <div className="know">
      <p className="know-hint">What each party holds after step {stepNo}.</p>
      <div className="know-grid">
        {ORDER.map((actor) => {
          const slot = forActor(actor);
          const has = [...slot.has];
          const lacks = [...slot.lacks];
          return (
            <div className="know-cell" key={actor}>
              <span className="know-name">{ACTOR_LABELS[actor]}</span>
              <span className="know-chips">
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
            </div>
          );
        })}
      </div>
    </div>
  );
}
