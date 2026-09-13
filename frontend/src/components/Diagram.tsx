import { ACTOR_LABELS, type Actor, type StepEvent } from "../types/trace";

interface Props {
  event: StepEvent | null;
}

const NODES: Record<Actor, { x: number; y: number; sub: string }> = {
  client: { x: 90, y: 60, sub: "Relying party" },
  auth_server: { x: 410, y: 60, sub: "IdP / issues tokens" },
  resource_server: { x: 410, y: 250, sub: "Protects the API" },
  attacker: { x: 90, y: 250, sub: "Adversary" },
};

const W = 170;
const H = 74;

function isActor(v: string | null | undefined): v is Actor {
  return (
    v === "client" ||
    v === "auth_server" ||
    v === "resource_server" ||
    v === "attacker"
  );
}

function center(a: Actor) {
  return { x: NODES[a].x + W / 2, y: NODES[a].y + H / 2 };
}

// The actor diagram: four parties, with the active message drawn between them.
// It is a pure function of the trace — the message edge comes from the explicit
// source/target actors the emitter records, never from string-matching hostnames.
export function Diagram({ event }: Props) {
  const activeActor = event?.actor ?? null;
  const onBehalf = event?.on_behalf_of ?? null;
  const src = event?.http?.source_actor ?? null;
  const tgt = event?.http?.target_actor ?? null;
  const source = isActor(src) ? src : null;
  const target = isActor(tgt) ? tgt : null;
  const drawEdge = source && target && source !== target;

  // Amber belongs to the attacker: the whole exchange reads as adversarial when
  // the attacker is the active actor or is being acted for.
  const attackerInvolved = onBehalf === "attacker" || activeActor === "attacker";

  return (
    <svg
      className="diagram"
      viewBox="0 0 600 340"
      role="img"
      aria-label={
        event
          ? `Step ${event.seq}: ${ACTOR_LABELS[event.actor]} is active. ${event.summary}`
          : "OAuth actor diagram"
      }
    >
      <defs>
        <marker
          id="arrow-accent"
          viewBox="0 0 10 10"
          refX="8"
          refY="5"
          markerWidth="7"
          markerHeight="7"
          orient="auto-start-reverse"
        >
          <path d="M 0 0 L 10 5 L 0 10 z" className="edge-arrow" />
        </marker>
        <marker
          id="arrow-attacker"
          viewBox="0 0 10 10"
          refX="8"
          refY="5"
          markerWidth="7"
          markerHeight="7"
          orient="auto-start-reverse"
        >
          <path d="M 0 0 L 10 5 L 0 10 z" className="edge-arrow edge-arrow-att" />
        </marker>
      </defs>

      {drawEdge && source && target && (
        <line
          x1={center(source).x}
          y1={center(source).y}
          x2={center(target).x}
          y2={center(target).y}
          className={`edge-line ${attackerInvolved ? "edge-line-att" : ""}`}
          markerEnd={`url(#${attackerInvolved ? "arrow-attacker" : "arrow-accent"})`}
        />
      )}

      {(Object.keys(NODES) as Actor[]).map((actor) => {
        const n = NODES[actor];
        const isActive = actor === activeActor;
        const isAttacker = actor === "attacker";
        const isIdle = isAttacker && !attackerInvolved;
        const boxClass =
          isAttacker && attackerInvolved
            ? "nb-attacker"
            : isActive
              ? "nb-active"
              : "nb-idle";
        return (
          <g key={actor}>
            <rect
              x={n.x}
              y={n.y}
              width={W}
              height={H}
              rx={10}
              className={`node-box ${boxClass} ${isIdle ? "nb-dashed" : ""}`}
            />
            <text x={n.x + 12} y={n.y + 28} className="node-title">
              {ACTOR_LABELS[actor]}
              {isActive ? " ●" : ""}
            </text>
            <text x={n.x + 12} y={n.y + 50} className="node-sub">
              {isIdle ? `${n.sub} (idle)` : n.sub}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
