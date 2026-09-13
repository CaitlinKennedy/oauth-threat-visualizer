import type { Verdict } from "../types/trace";

interface Props {
  verdict: Verdict;
}

// Pass/fail is never conveyed by color alone: each badge carries an icon glyph
// and a text label as well as a color class.
export function VerdictBanner({ verdict }: Props) {
  return (
    <div
      className="verdict"
      role="status"
      aria-live="polite"
      aria-label={`Verdict: ${verdict.one_line}`}
    >
      <div className="verdict-badges">
        <Badge
          ok={verdict.user_got_token && verdict.user_accessed_resource}
          okText="User obtained a token & reached the API"
          failText="User did not complete the flow"
        />
        <Badge
          ok={!verdict.attacker_got_token}
          okText="Attacker obtained no token"
          failText="Attacker obtained a token"
        />
      </div>
      <p className="verdict-line">{verdict.one_line}</p>
      {verdict.responsible_capability && (
        <p className="verdict-cap">
          Responsible mitigation: <strong>{verdict.responsible_capability}</strong>
          {verdict.blocked_at_seq != null && <> (blocked at step {verdict.blocked_at_seq})</>}
        </p>
      )}
    </div>
  );
}

function Badge({
  ok,
  okText,
  failText,
}: {
  ok: boolean;
  okText: string;
  failText: string;
}) {
  // Callers pass `ok` already meaning the *good* outcome for that badge.
  return (
    <span className={`badge ${ok ? "badge-good" : "badge-bad"}`}>
      <span className="badge-icon" aria-hidden="true">
        {ok ? "✓" : "✗"}
      </span>
      <span className="badge-text">{ok ? okText : failText}</span>
    </span>
  );
}
