import type { ReactNode } from "react";

export interface ScenarioCard {
  key: string;
  kicker: string;
  name: string;
  description: string;
  available: boolean;
  selected: boolean;
  onSelect: () => void;
}

export interface Chip {
  text: string;
  kind: "active" | "attack" | "neutral";
}

export interface GrantOption {
  id: string;
  label: string;
  one: string;
  spec: string;
  selected: boolean;
  onSelect: () => void;
}

export interface FeatureRow {
  id: string;
  label: string;
  one: string;
  spec: string;
  on: boolean;
  onToggle: () => void;
}

interface Props {
  scenarioName: string;
  stepNo: number;
  total: number;
  chips: Chip[];
  activeCount: number;
  scenarioOpen: boolean;
  configOpen: boolean;
  onToggleScenario: () => void;
  onToggleConfig: () => void;
  onWordmark: () => void;
  onHelp: () => void;
  scenarioCards: ScenarioCard[];
  grants: GrantOption[];
  grantLabel: string;
  grantNote: string;
  capabilities: FeatureRow[];
  attacks: FeatureRow[];
  configAvailable: boolean;
  coach?: ReactNode;
}

// The sticky command bar: the only permanent place configuration lives. The
// preset picker and the capability/attack catalog are two popovers, closed by
// default, summarised as chips. Everything here maps onto a ScenarioConfig the
// backend runs — the UI stays a pure function of the resulting trace.
export function CommandBar(props: Props) {
  const {
    scenarioName,
    stepNo,
    total,
    chips,
    activeCount,
    scenarioOpen,
    configOpen,
    onToggleScenario,
    onToggleConfig,
    onWordmark,
    onHelp,
    scenarioCards,
    grants,
    grantLabel,
    grantNote,
    capabilities,
    attacks,
    configAvailable,
    coach,
  } = props;

  return (
    <div className="cmdbar">
      <div className="cmdbar-row">
        <button
          className="cmdbar-wordmark"
          title="Back to the overview"
          onClick={onWordmark}
        >
          OAuth Threat Visualizer
        </button>

        <button
          className={`popover-trigger ${scenarioOpen ? "open" : ""}`}
          aria-expanded={scenarioOpen}
          onClick={onToggleScenario}
        >
          <span className="kicker">SCENARIO</span>
          <span className="trigger-name">{scenarioName}</span>
          <span className="caret" aria-hidden="true">
            ▾
          </span>
        </button>

        <button
          className={`popover-trigger ${configOpen ? "open" : ""}`}
          aria-expanded={configOpen}
          onClick={onToggleConfig}
        >
          <span className="trigger-name">Capabilities &amp; attacks</span>
          <span className="count-pill">{activeCount}</span>
          <span className="caret" aria-hidden="true">
            ▾
          </span>
        </button>

        <span className="cmdbar-chips">
          {chips.map((c, i) => (
            <span
              key={`${c.text}-${i}`}
              className={`chip-pill ${
                c.kind === "active"
                  ? "chip-active"
                  : c.kind === "attack"
                    ? "chip-attack"
                    : ""
              }`}
            >
              {c.text}
            </span>
          ))}
        </span>

        <button className="cmdbar-help" title="Show me around" onClick={onHelp}>
          ?
        </button>
        <span className="cmdbar-step">
          Step {stepNo} / {total}
        </span>
      </div>

      {coach}

      {scenarioOpen && (
        <div className="popover">
          <div className="popover-inner">
            <div className="scenario-grid">
              {scenarioCards.map((card) => (
                <button
                  key={card.key}
                  className={`scenario-card ${card.available ? "available" : ""}`}
                  onClick={card.onSelect}
                  aria-pressed={card.selected}
                >
                  <span className="kicker">{card.kicker}</span>
                  <span className="card-name">{card.name}</span>
                  <span className="card-desc">{card.description}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {configOpen && (
        <div className="popover">
          <div className="popover-inner">
            {configAvailable ? (
              <div className="config-grid">
                <div>
                  <h3 className="config-h">1 · Grant type</h3>
                  <div className="config-list" role="radiogroup" aria-label="Grant type">
                    {grants.map((g) => (
                      <button
                        key={g.id}
                        className={`config-row ${g.selected ? "selected" : ""}`}
                        role="radio"
                        aria-checked={g.selected}
                        onClick={g.onSelect}
                      >
                        <span className="config-radio" aria-hidden="true" />
                        <span className="config-label">{g.label}</span>
                        <span className="config-one">{g.one}</span>
                        <span className="config-spec">{g.spec}</span>
                      </button>
                    ))}
                  </div>

                  <h3 className="config-h spaced">2 · Extensions</h3>
                  <FeatureList
                    rows={capabilities}
                    empty="No extensions apply to this grant."
                  />
                  <p className="config-note">{grantNote}</p>
                </div>

                <div>
                  <h3 className="config-h">3 · Attacks that apply to {grantLabel}</h3>
                  <FeatureList
                    rows={attacks}
                    empty="No attacks apply to this grant."
                  />
                  <p className="config-note">
                    Toggling a capability re-runs the same attack — the two runs
                    stay identical until they diverge at one step.
                  </p>
                </div>
              </div>
            ) : (
              <p className="config-note">
                The capability catalog is unavailable right now (the backend could
                not be reached). The bundled demo trace is still playable.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function FeatureList({ rows, empty }: { rows: FeatureRow[]; empty: string }) {
  if (rows.length === 0) return <p className="config-note">{empty}</p>;
  return (
    <div className="config-list">
      {rows.map((r) => (
        <button
          key={r.id}
          className={`config-row ${r.on ? "on" : ""}`}
          role="checkbox"
          aria-checked={r.on}
          onClick={r.onToggle}
        >
          <span className="config-check" aria-hidden="true">
            {r.on ? "✓" : ""}
          </span>
          <span className="config-label">{r.label}</span>
          <span className="config-one">{r.one}</span>
          <span className="config-spec">{r.spec}</span>
        </button>
      ))}
    </div>
  );
}
