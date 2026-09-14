import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ApiError,
  fallbackTrace,
  fetchCatalog,
  fetchPresets,
  runCompare,
  runScenario,
} from "./api";
import type {
  Catalog,
  CompareResponse,
  Preset,
  ScenarioConfig,
  Trace,
} from "./types/trace";
import { Landing } from "./components/Landing";
import {
  CommandBar,
  type Chip,
  type FeatureRow,
  type GrantOption,
  type ScenarioCard,
} from "./components/CommandBar";
import { Coachmark } from "./components/Coachmarks";
import { Diagram } from "./components/Diagram";
import { Controls } from "./components/Controls";
import { StepCard, type Depth } from "./components/StepCard";
import { Timeline } from "./components/Timeline";
import { VerdictBanner } from "./components/VerdictBanner";
import { CompareBar } from "./components/CompareBar";
import { LessonBar } from "./components/LessonBar";

const AUTOPLAY_MS = 1600;
const COACH_KEY = "otv_coach_seen";

function prefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    window.matchMedia?.("(prefers-reduced-motion: reduce)").matches
  );
}

type Side = "baseline" | "variant";

// Grant metadata is fixed enum content (the catalog carries features, not grants).
const GRANT_META: Record<string, { label: string; one: string; spec: string; note: string }> = {
  authorization_code: {
    label: "Authorization Code",
    one: "redirect → code → back-channel exchange",
    spec: "RFC 6749 §4.1",
    note: "PKCE, state and issuer identification only exist in a redirect-based flow, so they appear here and nowhere else.",
  },
  client_credentials: {
    label: "Client Credentials",
    one: "machine-to-machine; static id + secret",
    spec: "RFC 6749 §4.4",
    note: "No user, no redirect — so no PKCE or state. The weak point is the secret itself, which never rotates.",
  },
  jwt_bearer: {
    label: "JWT Bearer",
    one: "short-lived signed assertion for a token",
    spec: "RFC 7523",
    note: "Replaces the static secret with a key-signed, short-lived assertion — the contrast case for a leaked secret.",
  },
};
const GRANT_ORDER = ["authorization_code", "client_credentials", "jwt_bearer"];

// The scenario cards / lessons are functionally labelled (never "Flow 1/2/3")
// and map onto real presets served by GET /api/scenarios. The "Defense" card is
// the paired-diff compare preset — the flip-PKCE gesture.
interface ScenarioDef {
  key: string;
  kicker: string;
  name: string;
  description: string;
  presetId: string;
}
const SCENARIO_DEFS: ScenarioDef[] = [
  {
    key: "basics",
    kicker: "Basics",
    name: "OAuth 2.0",
    description: "How OAuth 2.0 works, end to end.",
    presetId: "happy_path_auth_code",
  },
  {
    key: "attack",
    kicker: "Attack",
    name: "Auth-code injection",
    description: "What an attacker does when nothing stops them.",
    presetId: "injection_no_pkce",
  },
  {
    key: "defense",
    kicker: "Defense",
    name: "PKCE extension",
    description: "How PKCE defends against auth-code injection.",
    presetId: "injection_pkce_compare",
  },
];
const LESSONS = SCENARIO_DEFS.map((s) => ({ name: s.name, blurb: s.description }));

// A scenario selection is one of the three lessons, or the sandbox.
type Scenario = number | "playground";

function activeIds(map: Record<string, { active: boolean }> | undefined): string[] {
  return Object.entries(map ?? {})
    .filter(([, v]) => v?.active)
    .map(([k]) => k);
}

export default function App() {
  const [presets, setPresets] = useState<Preset[]>([]);
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [trace, setTrace] = useState<Trace | null>(null);
  const [compare, setCompare] = useState<CompareResponse | null>(null);
  const [side, setSide] = useState<Side>("variant");
  const [status, setStatus] = useState<string>("Loading…");

  const [screen, setScreen] = useState<"landing" | "run">("landing");
  const [scenario, setScenario] = useState<Scenario>(0);
  const [index, setIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [depth, setDepth] = useState<Depth>(1);
  const [scenarioOpen, setScenarioOpen] = useState(false);
  const [configOpen, setConfigOpen] = useState(false);
  const [verdictOpen, setVerdictOpen] = useState(false);
  const [coach, setCoach] = useState(0);

  // Playground config — kept in sync with whatever run is currently shown so the
  // popover reflects reality, and editable to run a custom scenario.
  const [grant, setGrant] = useState<string>("authorization_code");
  const [caps, setCaps] = useState<string[]>([]);
  const [atks, setAtks] = useState<string[]>([]);

  // The UI is a pure function of ONE trace: in compare mode that's the selected
  // side of the diff, otherwise the single run.
  const shownTrace = compare ? compare[side] : trace;
  const events = shownTrace?.events ?? [];
  const current = events[index] ?? null;
  const divergenceSeq = compare?.divergences[0]?.seq ?? null;

  // Keep the playground config mirror aligned with a freshly loaded run.
  const syncConfigFromTrace = useCallback((t: Trace) => {
    setGrant(t.config.grant);
    setCaps(activeIds(t.config.capabilities));
    setAtks(activeIds(t.config.attacks));
  }, []);

  const loadPreset = useCallback(
    async (preset: Preset) => {
      setPlaying(false);
      setIndex(0);
      setStatus(`Running: ${preset.name}…`);
      try {
        if (preset.mode === "compare" && preset.compare) {
          const resp = await runCompare(preset.compare.baseline, preset.compare.variant);
          setCompare(resp);
          setTrace(null);
          setSide("variant");
          syncConfigFromTrace(resp.variant);
          setStatus("Compare loaded — flip PKCE to watch the runs diverge.");
        } else {
          const t = await runScenario(preset.config);
          setCompare(null);
          setTrace(t);
          syncConfigFromTrace(t);
          setStatus(
            t._source === "fallback" ? "Loaded (fixture fallback)." : "Live run loaded.",
          );
        }
      } catch (err) {
        if (err instanceof ApiError) {
          setStatus(`${preset.name} is not available: ${err.message}`);
          return;
        }
        setCompare(null);
        setTrace(fallbackTrace());
        setStatus("Backend unreachable — showing bundled demo trace.");
      }
    },
    [syncConfigFromTrace],
  );

  // Select one of the three lessons/scenarios: load its preset if the backend
  // has it, else surface why.
  const selectScenario = useCallback(
    (lessonIndex: number) => {
      const def = SCENARIO_DEFS[lessonIndex];
      setScenario(lessonIndex);
      setScenarioOpen(false);
      const preset = presets.find((p) => p.id === def.presetId);
      if (preset && preset.available) {
        void loadPreset(preset);
      } else {
        setStatus(`${def.name} is not available in this build yet.`);
      }
    },
    [presets, loadPreset],
  );

  // Run an ad-hoc playground config. Non-200s (e.g. a not-yet-built combo → 501)
  // surface the server's message and keep the current trace on screen.
  const runPlayground = useCallback(
    async (g: string, c: string[], a: string[]) => {
      const config: ScenarioConfig = {
        grant: g as ScenarioConfig["grant"],
        capabilities: Object.fromEntries(c.map((id) => [id, { active: true }])),
        attacks: Object.fromEntries(a.map((id) => [id, { active: true, params: {} }])),
      };
      setScenario("playground");
      setPlaying(false);
      setIndex(0);
      setStatus("Running your configuration…");
      try {
        const t = await runScenario(config);
        setCompare(null);
        setTrace(t);
        setStatus(t._source === "fallback" ? "Loaded (fixture fallback)." : "Live run loaded.");
      } catch (err) {
        if (err instanceof ApiError) {
          setStatus(`That configuration is not available: ${err.message}`);
          return;
        }
        setStatus("Backend unreachable — keeping the current trace.");
      }
    },
    [],
  );

  const onGrant = useCallback(
    (id: string) => {
      // Changing the grant clears extensions and attacks (they may not apply).
      setGrant(id);
      setCaps([]);
      setAtks([]);
      void runPlayground(id, [], []);
    },
    [runPlayground],
  );
  const onToggleCap = useCallback(
    (id: string) => {
      const nextCaps = caps.includes(id) ? caps.filter((x) => x !== id) : [...caps, id];
      setCaps(nextCaps);
      void runPlayground(grant, nextCaps, atks);
    },
    [caps, atks, grant, runPlayground],
  );
  const onToggleAtk = useCallback(
    (id: string) => {
      const nextAtks = atks.includes(id) ? atks.filter((x) => x !== id) : [...atks, id];
      setAtks(nextAtks);
      void runPlayground(grant, caps, nextAtks);
    },
    [caps, atks, grant, runPlayground],
  );

  // Boot in demo mode: load presets + catalog and immediately run the default.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const [presetsRes, catalogRes] = await Promise.allSettled([
        fetchPresets(),
        fetchCatalog(),
      ]);
      if (cancelled) return;

      if (catalogRes.status === "fulfilled") setCatalog(catalogRes.value);

      if (presetsRes.status === "fulfilled") {
        const p = presetsRes.value;
        setPresets(p.presets);
        const preset =
          p.presets.find((x) => x.id === p.default_preset) ?? p.presets[0];
        if (preset) await loadPreset(preset);
        else {
          setTrace(fallbackTrace());
          setStatus("No scenarios returned — showing bundled demo trace.");
        }
      } else {
        setTrace(fallbackTrace());
        setStatus("Backend unreachable — showing bundled demo trace.");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [loadPreset]);

  const next = useCallback(() => {
    setIndex((i) => Math.min(i + 1, events.length - 1));
  }, [events.length]);
  const prev = useCallback(() => setIndex((i) => Math.max(i - 1, 0)), []);
  const restart = useCallback(() => {
    setPlaying(false);
    setIndex(0);
  }, []);

  // Flip which run is shown, keeping the step position (clamped) so the reader
  // sees the SAME step change outcome — the core of the gesture.
  const setSideKeepStep = useCallback(
    (s: Side) => {
      setPlaying(false);
      setSide(s);
      if (compare) {
        const len = compare[s].events.length;
        setIndex((i) => Math.min(i, Math.max(0, len - 1)));
      }
    },
    [compare],
  );

  // One-click "video" auto-play. Honors prefers-reduced-motion.
  const timer = useRef<number | null>(null);
  useEffect(() => {
    if (!playing || screen !== "run") return;
    if (index >= events.length - 1) {
      setPlaying(false);
      return;
    }
    const delay = prefersReducedMotion() ? AUTOPLAY_MS + 600 : AUTOPLAY_MS;
    timer.current = window.setTimeout(() => setIndex((i) => i + 1), delay);
    return () => {
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, [playing, index, events.length, screen]);

  // Keyboard: arrows step, space plays, Home/End jump, Esc closes popovers, and
  // in compare mode "p" flips PKCE. Only bound on the run screen; ignored while a
  // field is focused.
  useEffect(() => {
    if (screen !== "run") return;
    function onKey(e: KeyboardEvent) {
      const target = e.target as HTMLElement | null;
      const tag = target?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA") return;
      if (e.key === "ArrowRight") {
        e.preventDefault();
        next();
      } else if (e.key === "ArrowLeft") {
        e.preventDefault();
        prev();
      } else if (e.key === " ") {
        if (
          tag === "BUTTON" ||
          tag === "A" ||
          tag === "SELECT" ||
          target?.getAttribute?.("role") === "button" ||
          target?.isContentEditable
        ) {
          return;
        }
        e.preventDefault();
        setPlaying((p) => !p);
      } else if (e.key === "Home") {
        setIndex(0);
      } else if (e.key === "End") {
        setIndex(events.length - 1);
      } else if (e.key === "Escape") {
        setScenarioOpen(false);
        setConfigOpen(false);
      } else if ((e.key === "p" || e.key === "P") && compare) {
        e.preventDefault();
        setSideKeepStep(side === "variant" ? "baseline" : "variant");
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [screen, next, prev, events.length, compare, side, setSideKeepStep]);

  // Coachmark tour: shown once on first entry to the run view, persisted in
  // localStorage; re-openable from the `?` button.
  const startCoach = useCallback(() => {
    setPlaying(false);
    setCoach(1);
  }, []);
  const dismissCoach = useCallback(() => {
    setCoach(0);
    try {
      window.localStorage?.setItem(COACH_KEY, "1");
    } catch {
      /* private mode / blocked storage — the tour simply shows again */
    }
  }, []);
  const enterRun = useCallback(
    (opts?: { playground?: boolean; play?: boolean }) => {
      setScreen("run");
      setIndex(0);
      setPlaying(!!opts?.play);
      if (opts?.playground) setConfigOpen(true);
      let seen = false;
      try {
        seen = window.localStorage?.getItem(COACH_KEY) === "1";
      } catch {
        seen = false;
      }
      if (!seen) setCoach(1);
    },
    [],
  );

  // --- Derived view models -------------------------------------------------
  const catalogLabels = useMemo(() => {
    const m: Record<string, string> = {};
    if (catalog) {
      for (const it of [...catalog.capabilities, ...catalog.attacks]) m[it.id] = it.label;
    }
    return m;
  }, [catalog]);

  const cfg = shownTrace?.config;
  const chips: Chip[] = useMemo(() => {
    if (!cfg) return [];
    const out: Chip[] = [
      { text: (GRANT_META[cfg.grant]?.label ?? cfg.grant).toLowerCase(), kind: "active" },
    ];
    for (const id of activeIds(cfg.capabilities)) {
      out.push({ text: catalogLabels[id] ?? id, kind: "active" });
    }
    const a = activeIds(cfg.attacks);
    if (a.length) {
      for (const id of a) out.push({ text: (catalogLabels[id] ?? id).toLowerCase(), kind: "attack" });
    } else {
      out.push({ text: "no attack", kind: "neutral" });
    }
    return out;
  }, [cfg, catalogLabels]);

  const activeCount = cfg
    ? 1 + activeIds(cfg.capabilities).length + activeIds(cfg.attacks).length
    : 1;

  const scenarioName = scenario === "playground" ? "Playground" : SCENARIO_DEFS[scenario].name;

  const scenarioCards: ScenarioCard[] = useMemo(() => {
    const lessonCards = SCENARIO_DEFS.map((def, i) => {
      const preset = presets.find((p) => p.id === def.presetId);
      return {
        key: def.key,
        kicker: def.kicker,
        name: def.name,
        description: def.description,
        available: !!preset && !!preset.available,
        selected: scenario === i,
        onSelect: () => selectScenario(i),
      };
    });
    lessonCards.push({
      key: "sandbox",
      kicker: "Sandbox",
      name: "Playground",
      description: "Pick your own capabilities and attacks.",
      available: !!catalog,
      selected: scenario === "playground",
      onSelect: () => {
        setScenario("playground");
        setScenarioOpen(false);
        setConfigOpen(true);
      },
    });
    return lessonCards;
  }, [presets, catalog, scenario, selectScenario]);

  const grantOptions: GrantOption[] = GRANT_ORDER.map((id) => ({
    id,
    label: GRANT_META[id].label,
    one: GRANT_META[id].one,
    spec: GRANT_META[id].spec,
    selected: grant === id,
    onSelect: () => onGrant(id),
  }));

  const capRows: FeatureRow[] = useMemo(() => {
    if (!catalog) return [];
    return catalog.capabilities
      .filter((it) => it.applies_to_grants.length === 0 || it.applies_to_grants.includes(grant))
      .map((it) => ({
        id: it.id,
        label: it.label,
        one: it.description,
        spec: `${it.spec_ref.rfc} ${it.spec_ref.section}`,
        on: caps.includes(it.id),
        disabled: !it.available,
        onToggle: () => onToggleCap(it.id),
      }));
  }, [catalog, grant, caps, onToggleCap]);

  const atkRows: FeatureRow[] = useMemo(() => {
    if (!catalog) return [];
    return catalog.attacks
      .filter((it) => it.applies_to_grants.length === 0 || it.applies_to_grants.includes(grant))
      .map((it) => ({
        id: it.id,
        label: it.label,
        one: it.description,
        spec: `${it.spec_ref.rfc} ${it.spec_ref.section}`,
        on: atks.includes(it.id),
        disabled: !it.available,
        onToggle: () => onToggleAtk(it.id),
      }));
  }, [catalog, grant, atks, onToggleAtk]);

  // --- Render --------------------------------------------------------------
  if (screen === "landing") {
    return (
      <Landing
        onStart={() => {
          selectScenario(0);
          enterRun();
        }}
        onPlayground={() => {
          setScenario("playground");
          enterRun({ playground: true });
        }}
      />
    );
  }

  return (
    <div className="run">
      <CommandBar
        scenarioName={scenarioName}
        stepNo={Math.min(index + 1, Math.max(events.length, 1))}
        total={events.length}
        chips={chips}
        activeCount={activeCount}
        scenarioOpen={scenarioOpen}
        configOpen={configOpen}
        onToggleScenario={() =>
          setScenarioOpen((o) => {
            if (!o) setConfigOpen(false);
            return !o;
          })
        }
        onToggleConfig={() =>
          setConfigOpen((o) => {
            if (!o) setScenarioOpen(false);
            return !o;
          })
        }
        onWordmark={() => {
          setScreen("landing");
          setPlaying(false);
          setScenarioOpen(false);
          setConfigOpen(false);
        }}
        onHelp={startCoach}
        scenarioCards={scenarioCards}
        grants={grantOptions}
        grantLabel={GRANT_META[grant]?.label ?? grant}
        grantNote={GRANT_META[grant]?.note ?? ""}
        capabilities={capRows}
        attacks={atkRows}
        configAvailable={!!catalog}
        coach={
          coach === 1 ? (
            <Coachmark
              place="coach-1"
              kicker="1 OF 3"
              body={
                <>
                  Everything you can change lives here. Pick a scenario, or open{" "}
                  <strong>Capabilities &amp; attacks</strong> to switch a defense on
                  and re-run.
                </>
              }
              onNext={() => setCoach(2)}
              onSkip={dismissCoach}
            />
          ) : null
        }
      />

      <div className="run-body">
        {compare && (
          <CompareBar
            compare={compare}
            side={side}
            onSetSide={setSideKeepStep}
            currentSeq={current?.seq ?? null}
            catalogLabels={catalogLabels}
          />
        )}

        {shownTrace && (
          <VerdictBanner
            trace={shownTrace}
            open={verdictOpen}
            onToggle={() => setVerdictOpen((o) => !o)}
            catalogLabels={catalogLabels}
          />
        )}

        <div className="stage">
          <div className="stage-left">
            <div className="card diagram-card">
              {coach === 2 && (
                <Coachmark
                  place="coach-2"
                  kicker="2 OF 3"
                  body={
                    <>
                      The four parties, with the active message drawn between them.
                      Press <strong>Play</strong> to run it hands-off, or step with ← →.
                    </>
                  }
                  onNext={() => setCoach(3)}
                  onSkip={dismissCoach}
                />
              )}
              <Diagram event={current} />
              <Controls
                total={events.length}
                currentIndex={index}
                playing={playing}
                onPrev={prev}
                onNext={next}
                onTogglePlay={() => setPlaying((p) => !p)}
                onRestart={restart}
                onScrub={(i) => {
                  setPlaying(false);
                  setIndex(i);
                }}
              />
            </div>

            <StepCard
              event={current}
              depth={depth}
              onDepth={setDepth}
              events={events}
              currentIndex={index}
            />
          </div>

          <div className="stage-right">
            <div className="rail-wrap">
              {coach === 3 && (
                <Coachmark
                  place="coach-3"
                  kicker="3 OF 3"
                  last
                  body={
                    <>
                      Every step, with ✓ / ✗ where the protocol makes a decision.
                      Jump to any of them — the step card on the left shows the detail.
                    </>
                  }
                  onNext={dismissCoach}
                  onSkip={dismissCoach}
                />
              )}
              <Timeline
                events={events}
                currentIndex={index}
                divergenceSeq={divergenceSeq}
                onSelect={(i) => {
                  setPlaying(false);
                  setIndex(i);
                }}
              />
            </div>
            {shownTrace && (
              <p className="rail-foot">
                run {shownTrace.correlation_id.slice(0, 14)}… ·{" "}
                {shownTrace._source === "fallback" ? "bundled demo trace" : "live run"}
              </p>
            )}
            <p className="status-line" role="status" aria-live="polite">
              {status}
            </p>
          </div>
        </div>

        {scenario !== "playground" && (
          <LessonBar
            lessons={LESSONS}
            current={typeof scenario === "number" ? scenario : 0}
            onSelect={(i) => selectScenario(i)}
            onNext={() =>
              selectScenario(Math.min((typeof scenario === "number" ? scenario : 0) + 1, LESSONS.length - 1))
            }
          />
        )}
      </div>
    </div>
  );
}
