import { useState } from "react";
import {
  ACTOR_LABELS,
  type HttpMessage,
  type StepEvent,
} from "../types/trace";

interface Props {
  event: StepEvent | null;
}

const DEPTHS = [
  { level: 1, label: "Summary" },
  { level: 2, label: "Detail" },
  { level: 3, label: "Exact HTTP" },
  { level: 4, label: "Spec" },
] as const;

// Progressive disclosure at four depths (DESIGN.md §7): one-liner → paragraph →
// exact HTTP → the RFC clause. The depth control reveals cumulatively.
export function DrillDown({ event }: Props) {
  const [depth, setDepth] = useState(1);
  if (!event) return <div className="drilldown">No step selected.</div>;

  return (
    <div className="drilldown">
      <div className="drilldown-head">
        <h2 className="panel-title">
          Step {event.seq} · {ACTOR_LABELS[event.actor]}
          <span className="phase-tag">{event.phase}</span>
          <OutcomeTag outcome={event.outcome} />
        </h2>
        <div className="depth-controls" role="group" aria-label="Drill-down depth">
          {DEPTHS.map((d) => (
            <button
              key={d.level}
              className={`depth-btn ${depth >= d.level ? "depth-on" : ""}`}
              aria-pressed={depth >= d.level}
              onClick={() => setDepth(d.level)}
            >
              {d.label}
            </button>
          ))}
        </div>
      </div>

      {/* Depth 1 */}
      <p className="depth-summary">{event.summary}</p>
      {event.on_behalf_of !== "user" && (
        <p className="on-behalf">Acting on behalf of: {event.on_behalf_of}</p>
      )}

      {/* Depth 2 */}
      {depth >= 2 && <p className="depth-detail">{event.detail}</p>}

      {/* A check is a first-class mitigation point; always show when present at depth >=2 */}
      {depth >= 2 && event.check && (
        <div className={`check check-${event.check.result.toLowerCase()}`}>
          <div className="check-head">
            <span className="check-icon" aria-hidden="true">
              {event.check.result === "PASS" ? "✓" : "✗"}
            </span>
            <span className="check-name">{event.check.name}</span>
            <span className="check-result">{event.check.result}</span>
          </div>
          <code className="check-rule">{event.check.rule}</code>
          {(event.check.expected || event.check.actual) && (
            <div className="check-ea">
              <span>expected: {event.check.expected ?? "—"}</span>
              <span>actual: {event.check.actual ?? "—"}</span>
            </div>
          )}
          <div className="check-spec">
            mandated by {event.check.spec_ref.rfc} {event.check.spec_ref.section}
          </div>
        </div>
      )}

      {/* Depth 3 */}
      {depth >= 3 && event.http && (
        <div className="http">
          <HttpBlock
            title="Request"
            side="request"
            msg={event.http.request}
            highlight={event.http.highlight}
          />
          <HttpBlock
            title="Response"
            side="response"
            msg={event.http.response}
            highlight={event.http.highlight}
          />
        </div>
      )}
      {depth >= 3 && !event.http && (
        <p className="muted">This step performs no HTTP exchange.</p>
      )}

      {/* Depth 4 */}
      {depth >= 4 && (
        <div className="spec-refs">
          <h3 className="spec-title">Governing specification</h3>
          {event.spec_refs.length === 0 && <p className="muted">No spec references.</p>}
          <ul>
            {event.spec_refs.map((s, i) => (
              <li key={i}>
                <strong>{s.rfc}</strong> {s.section}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function OutcomeTag({ outcome }: { outcome: StepEvent["outcome"] }) {
  const good = outcome === "ok" || outcome === "attack_blocked";
  return (
    <span className={`outcome-tag ${good ? "outcome-good" : "outcome-bad"}`}>
      <span aria-hidden="true">{good ? "✓ " : "✗ "}</span>
      {outcome}
    </span>
  );
}

// A highlight entry is a dotted path `<side>.<section>.<key>` (see contract). A
// field is decisive when the set holds that exact path; as a fallback (for any
// bare-key entries) the trailing segment is also matched.
function makeMatcher(highlight: string[], side: "request" | "response") {
  const set = new Set(highlight);
  const bareKeys = new Set(
    highlight.filter((h) => !h.includes(".")).map((h) => h),
  );
  return (section: "headers" | "body" | "query", key: string): boolean =>
    set.has(`${side}.${section}.${key}`) || bareKeys.has(key);
}

function HttpBlock({
  title,
  side,
  msg,
  highlight,
}: {
  title: string;
  side: "request" | "response";
  msg: HttpMessage;
  highlight: string[];
}) {
  const isHi = makeMatcher(highlight, side);
  const headers = msg.headers ? Object.entries(msg.headers) : [];
  return (
    <div className="http-block">
      <div className="http-line">
        <span className="http-title">{title}</span>
        {msg.method && <span className="http-method">{msg.method}</span>}
        {msg.url && <span className="http-url">{msg.url}</span>}
        {msg.status != null && <span className="http-status">{msg.status}</span>}
      </div>
      {headers.length > 0 && (
        <pre className="http-headers">
          {headers.map(([k, v]) => (
            <div key={k} className={isHi("headers", k) ? "kv kv-hi" : "kv"}>
              <span className="kv-key">
                {isHi("headers", k) && <span aria-hidden="true">▶ </span>}
                {k}
              </span>
              : {String(v)}
              {isHi("headers", k) && <span className="kv-flag"> ← decisive</span>}
            </div>
          ))}
        </pre>
      )}
      {msg.body != null && <BodyView body={msg.body} isHi={isHi} />}
    </div>
  );
}

function BodyView({
  body,
  isHi,
}: {
  body: unknown;
  isHi: (section: "headers" | "body" | "query", key: string) => boolean;
}) {
  if (body && typeof body === "object" && !Array.isArray(body)) {
    const entries = Object.entries(body as Record<string, unknown>);
    return (
      <pre className="http-body">
        {"{"}
        {entries.map(([k, v]) => (
          <div key={k} className={isHi("body", k) ? "kv kv-hi" : "kv"}>
            {"  "}
            <span className="kv-key">
              {isHi("body", k) && <span aria-hidden="true">▶ </span>}
              {JSON.stringify(k)}
            </span>
            : {truncate(JSON.stringify(v))}
            {isHi("body", k) && <span className="kv-flag"> ← decisive</span>}
          </div>
        ))}
        {"}"}
      </pre>
    );
  }
  return <pre className="http-body">{truncate(JSON.stringify(body))}</pre>;
}

function truncate(s: string, max = 96): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max)}…`;
}
