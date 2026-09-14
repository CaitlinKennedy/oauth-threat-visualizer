import type { Trace } from "../types/trace";

interface Props {
  trace: Trace;
  open: boolean;
  onToggle: () => void;
  catalogLabels?: Record<string, string>;
}

// The verdict strip. Pass/fail is never conveyed by color alone: each badge
// carries a ✓/✗ glyph and a text label. The "Why?" disclosure explains the
// outcome from fields on the trace, so it stays a pure function of the run.
export function VerdictBanner({ trace, open, onToggle, catalogLabels = {} }: Props) {
  const v = trace.verdict;
  const attackerWon = v.attacker_got_token;
  const anyAttack = Object.values(trace.config?.attacks ?? {}).some(
    (a) => a?.active,
  );
  const label = (id: string) => catalogLabels[id] ?? id;

  const responsible = !anyAttack
    ? "None needed — no attack was attempted in this run."
    : v.responsible_capability
      ? label(v.responsible_capability)
      : attackerWon
        ? "None — the attack succeeded."
        : "—";

  const blockedAt =
    v.blocked_at_seq != null
      ? `Step ${v.blocked_at_seq}`
      : !anyAttack
        ? `Nothing blocked; all ${trace.events.length} steps succeeded.`
        : attackerWon
          ? "Nothing blocked the attacker."
          : "—";

  return (
    <section
      className={`verdict ${attackerWon ? "verdict-lost" : ""}`}
      role="status"
      aria-live="polite"
      aria-label={`Verdict: ${v.one_line}`}
    >
      <Badge
        ok={!attackerWon}
        okText="Attacker gained access: NO"
        failText="Attacker gained access: YES"
      />
      <Badge
        ok={v.user_got_token && v.user_accessed_resource}
        okText="User reached the API"
        failText="User did not complete the flow"
      />
      <p className="verdict-line">{v.one_line}</p>
      <button
        className="verdict-why"
        aria-expanded={open}
        onClick={onToggle}
      >
        {open ? "Hide why" : "Why?"}
      </button>

      {open && (
        <div className="verdict-detail">
          <div>
            <p className="verdict-field-label">Responsible mitigation</p>
            <p className="verdict-field-value">{responsible}</p>
          </div>
          <div>
            <p className="verdict-field-label">Blocked at</p>
            <p className="verdict-field-value">{blockedAt}</p>
          </div>
          <div>
            <p className="verdict-field-label">The binding that held</p>
            <p className="verdict-field-value">{bindingText(trace)}</p>
          </div>
        </div>
      )}
    </section>
  );
}

// Derived entirely from the trace's checks: the FAIL that stopped an attacker,
// or the PASS bindings that carried a clean run.
function bindingText(trace: Trace): string {
  const v = trace.verdict;
  const withChecks = trace.events.filter((e) => e.check);
  if (v.attacker_got_token) {
    return "No binding stopped the attacker: the captured code or token was accepted with nothing per-request left to verify.";
  }
  const failed = withChecks.find((e) => e.check!.result === "FAIL");
  if (failed) {
    return `${failed.check!.name} failed at step ${failed.seq}: ${failed.check!.rule}.`;
  }
  const passed = withChecks.filter((e) => e.check!.result === "PASS");
  if (passed.length) {
    return (
      "Bindings held — " +
      passed.map((e) => `${e.check!.name} (step ${e.seq})`).join("; ") +
      "."
    );
  }
  return "The exchange completed with every protocol check satisfied.";
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
  return (
    <span className={`badge ${ok ? "badge-good" : "badge-bad"}`}>
      <span className="badge-icon" aria-hidden="true">
        {ok ? "✓" : "✗"}
      </span>
      <span className="badge-text">{ok ? okText : failText}</span>
    </span>
  );
}
