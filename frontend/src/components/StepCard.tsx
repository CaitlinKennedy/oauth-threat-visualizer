import {
  ACTOR_LABELS,
  type HttpMessage,
  type SpecRef,
  type StepEvent,
} from "../types/trace";
import { KnowledgeGrid } from "./KnowledgePanel";

export type Depth = 1 | 2 | 3;

interface Props {
  event: StepEvent | null;
  depth: Depth;
  onDepth: (d: Depth) => void;
  // For the "Who holds what" tab, which folds the ledger over steps 0..current.
  events: StepEvent[];
  currentIndex: number;
}

const DEPTHS: { level: Depth; label: string }[] = [
  { level: 1, label: "Summary" },
  { level: 2, label: "Detailed HTTP" },
  { level: 3, label: "Who holds what" },
];

function rfcUrl(rfc: string): string {
  const slug = rfc.toLowerCase().replace(/\s+/g, "");
  if (/^rfc\d+$/.test(slug)) return `https://www.rfc-editor.org/rfc/${slug}`;
  return "https://www.rfc-editor.org/";
}

// The step card. The three depths are mutually exclusive (not cumulative): the
// summary line is always shown, then exactly one of the paragraph+check+spec
// (Summary), the request/response (Detailed HTTP), or the actor ledger (Who
// holds what). The chosen depth is owned by App so it persists across steps —
// deliberate, so a reader can walk the whole run at HTTP depth.
export function StepCard({ event, depth, onDepth, events, currentIndex }: Props) {
  if (!event) return <div className="card stepcard">No step selected.</div>;

  const good = event.outcome === "ok" || event.outcome === "attack_blocked";

  return (
    <div className="card stepcard">
      <div className="stepcard-head">
        <h2 className="stepcard-title">
          Step {event.seq} · {ACTOR_LABELS[event.actor]}
          <span className="phase-tag">{event.phase}</span>
          <span className={`outcome-tag ${good ? "outcome-good" : "outcome-bad"}`}>
            <span aria-hidden="true">{good ? "✓ " : "✗ "}</span>
            {good ? "ok" : event.outcome}
          </span>
        </h2>
        <div className="seg" role="group" aria-label="Step detail depth">
          {DEPTHS.map((d) => (
            <button
              key={d.level}
              className={`seg-btn ${depth === d.level ? "seg-on" : ""}`}
              aria-pressed={depth === d.level}
              onClick={() => onDepth(d.level)}
            >
              {d.label}
            </button>
          ))}
        </div>
      </div>

      <p className="step-summary">{event.summary}</p>

      {depth === 1 && (
        <>
          {event.on_behalf_of !== "user" && (
            <p className="on-behalf">Acting on behalf of: {event.on_behalf_of}</p>
          )}
          <p className="step-detail">{event.detail}</p>
          {event.check && <CheckBlock check={event.check} />}
          <SpecLine refs={event.spec_refs} />
        </>
      )}

      {depth === 2 &&
        (event.http ? (
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
        ) : (
          <p className="muted">This step performs no HTTP exchange.</p>
        ))}

      {depth === 3 && (
        <KnowledgeGrid
          events={events}
          currentIndex={currentIndex}
          stepNo={event.seq}
        />
      )}
    </div>
  );
}

function CheckBlock({ check }: { check: NonNullable<StepEvent["check"]> }) {
  const pass = check.result === "PASS";
  return (
    <div className={`check ${pass ? "check-pass" : "check-fail"}`}>
      <div className="check-head">
        <span className="check-icon" aria-hidden="true">
          {pass ? "✓" : "✗"}
        </span>
        <span className="check-name">{check.name}</span>
        <span className="check-result">{check.result}</span>
      </div>
      <code className="check-rule">{check.rule}</code>
      {(check.expected || check.actual) && (
        <div className="check-ea">
          <span>expected: {check.expected ?? "—"}</span>
          <span>actual: {check.actual ?? "—"}</span>
        </div>
      )}
      <div className="check-spec">
        mandated by {check.spec_ref.rfc} {check.spec_ref.section}
      </div>
    </div>
  );
}

function SpecLine({ refs }: { refs: SpecRef[] }) {
  if (refs.length === 0) return null;
  return (
    <p className="spec-line">
      <span>Governed by</span>
      {refs.map((s, i) => (
        <a
          key={i}
          className="spec-link"
          href={rfcUrl(s.rfc)}
          target="_blank"
          rel="noopener noreferrer"
        >
          {s.rfc} {s.section} ↗
        </a>
      ))}
    </p>
  );
}

// A highlight entry is a dotted path `<side>.<section>.<key>` (see contract). A
// field is decisive when the set holds that exact path; as a fallback (for any
// bare-key entries) the trailing segment is also matched.
function makeMatcher(highlight: string[], side: "request" | "response") {
  const set = new Set(highlight);
  const bareKeys = new Set(highlight.filter((h) => !h.includes(".")));
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
              : {truncate(String(v), 110)}
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
            : {truncate(JSON.stringify(v), 96)}
            {isHi("body", k) && <span className="kv-flag"> ← decisive</span>}
          </div>
        ))}
        {"}"}
      </pre>
    );
  }
  return <pre className="http-body">{truncate(JSON.stringify(body), 96)}</pre>;
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max)}…`;
}
