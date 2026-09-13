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

// Map a URL host to the actor that owns it, so the active edge is derived from
// the real HTTP in the trace rather than hard-coded per step.
function actorForUrl(url?: string): Actor | null {
  if (!url) return null;
  if (url.includes("auth.oauthlab.internal")) return "auth_server";
  if (url.includes("api.oauthlab.internal")) return "resource_server";
  if (url.includes("app.oauthlab.internal")) return "client";
  return null;
}

function center(a: Actor) {
  return { x: NODES[a].x + W / 2, y: NODES[a].y + H / 2 };
}

export function Diagram({ event }: Props) {
  const activeActor = event?.actor ?? null;
  const onBehalf = event?.on_behalf_of ?? null;
  const target = event ? actorForUrl(event.http?.request?.url) : null;
  const source = activeActor;
  const drawEdge = source && target && source !== target;

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
      {drawEdge && source && target && (
        <Edge from={center(source)} to={center(target)} />
      )}

      {(Object.keys(NODES) as Actor[]).map((actor) => {
        const n = NODES[actor];
        const isActive = actor === activeActor;
        const isIdle = actor === "attacker" && !attackerInvolved;
        return (
          <g key={actor} className={`node ${isActive ? "node-active" : ""}`}>
            <rect
              x={n.x}
              y={n.y}
              width={W}
              height={H}
              rx={10}
              className={`node-box ${isActive ? "box-active" : ""} ${
                isIdle ? "box-idle" : ""
              }`}
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

function Edge({
  from,
  to,
}: {
  from: { x: number; y: number };
  to: { x: number; y: number };
}) {
  return (
    <g className="edge">
      <defs>
        <marker
          id="arrow"
          viewBox="0 0 10 10"
          refX="8"
          refY="5"
          markerWidth="7"
          markerHeight="7"
          orient="auto-start-reverse"
        >
          <path d="M 0 0 L 10 5 L 0 10 z" className="edge-arrow" />
        </marker>
      </defs>
      <line
        x1={from.x}
        y1={from.y}
        x2={to.x}
        y2={to.y}
        className="edge-line"
        markerEnd="url(#arrow)"
      />
    </g>
  );
}
