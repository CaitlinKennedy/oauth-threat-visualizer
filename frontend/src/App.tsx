import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { fallbackTrace, fetchCatalog, fetchPresets, runScenario } from "./api";
import type { Catalog, Preset, Trace } from "./types/trace";
import { Diagram } from "./components/Diagram";
import { Timeline } from "./components/Timeline";
import { Controls } from "./components/Controls";
import { DrillDown } from "./components/DrillDown";
import { VerdictBanner } from "./components/VerdictBanner";
import { KnowledgePanel } from "./components/KnowledgePanel";
import { CatalogStrip } from "./components/CatalogStrip";

const AUTOPLAY_MS = 1600;

function prefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    window.matchMedia?.("(prefers-reduced-motion: reduce)").matches
  );
}

export default function App() {
  const [presets, setPresets] = useState<Preset[]>([]);
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [trace, setTrace] = useState<Trace | null>(null);
  const [index, setIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [status, setStatus] = useState<string>("Loading…");

  const events = trace?.events ?? [];
  const current = events[index] ?? null;

  const loadPreset = useCallback(async (preset: Preset) => {
    setPlaying(false);
    setStatus(`Running: ${preset.name}…`);
    try {
      const t = await runScenario(preset.config);
      setTrace(t);
      setIndex(0);
      setStatus(t._source === "fallback" ? "Loaded (fixture fallback)." : "Live run loaded.");
    } catch {
      // Backend unreachable: use the bundled golden trace so the app still demos.
      setTrace(fallbackTrace());
      setIndex(0);
      setStatus("Backend unreachable — showing bundled demo trace.");
    }
  }, []);

  // Boot in demo mode: load presets + catalog and immediately run the default.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [p, c] = await Promise.all([fetchPresets(), fetchCatalog()]);
        if (cancelled) return;
        setPresets(p.presets);
        setCatalog(c);
        const preset =
          p.presets.find((x) => x.id === p.default_preset) ?? p.presets[0];
        await loadPreset(preset);
      } catch {
        if (cancelled) return;
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

  // One-click "video" auto-play. Honors prefers-reduced-motion by stepping
  // without relying on animated transitions (the CSS also disables them).
  const timer = useRef<number | null>(null);
  useEffect(() => {
    if (!playing) return;
    if (index >= events.length - 1) {
      setPlaying(false);
      return;
    }
    const delay = prefersReducedMotion() ? AUTOPLAY_MS + 600 : AUTOPLAY_MS;
    timer.current = window.setTimeout(() => setIndex((i) => i + 1), delay);
    return () => {
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, [playing, index, events.length]);

  // Keyboard stepping: arrows step, space toggles play, Home/End jump.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA") return;
      if (e.key === "ArrowRight") {
        e.preventDefault();
        next();
      } else if (e.key === "ArrowLeft") {
        e.preventDefault();
        prev();
      } else if (e.key === " ") {
        e.preventDefault();
        setPlaying((p) => !p);
      } else if (e.key === "Home") {
        setIndex(0);
      } else if (e.key === "End") {
        setIndex(events.length - 1);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [next, prev, events.length]);

  const runnablePresets = useMemo(() => presets, [presets]);

  return (
    <div className="app">
      <header className="app-header">
        <div>
          <h1 className="app-title">OAuth Threat Visualizer</h1>
          <p className="app-tagline">
            Watch a real OAuth exchange play out across four actors — drill from a
            one-line summary down to the exact HTTP and the RFC clause that governs it.
          </p>
        </div>
        <div className="preset-picker" role="group" aria-label="Scenario presets">
          {runnablePresets.map((p) => (
            <button
              key={p.id}
              className={`preset-btn ${trace?.config && sameConfig(p, trace) ? "preset-active" : ""}`}
              disabled={!p.available}
              title={p.available ? p.description : `${p.description} (coming soon)`}
              onClick={() => loadPreset(p)}
            >
              <span className="preset-flow">Flow {p.flow}</span>
              <span className="preset-name">{p.name}</span>
              {!p.available && <span className="preset-soon">soon</span>}
            </button>
          ))}
        </div>
      </header>

      {trace && <VerdictBanner verdict={trace.verdict} />}

      {catalog && <CatalogStrip catalog={catalog} />}

      <main className="app-main">
        <section className="col col-left">
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
          <KnowledgePanel events={events} currentIndex={index} />
        </section>

        <section className="col col-mid">
          <DrillDown event={current} />
        </section>

        <aside className="col col-right">
          <Timeline
            events={events}
            currentIndex={index}
            onSelect={(i) => {
              setPlaying(false);
              setIndex(i);
            }}
          />
        </aside>
      </main>

      <footer className="app-footer">
        <span className="status" role="status">
          {status}
        </span>
        {trace && <span className="corr">run {trace.correlation_id.slice(0, 14)}…</span>}
        <span className="hint">
          Keys: ← → step · space play/pause · Home/End jump
        </span>
      </footer>
    </div>
  );
}

function activeIds(m: Record<string, { active: boolean }>): string {
  return Object.entries(m)
    .filter(([, s]) => s.active)
    .map(([id]) => id)
    .sort()
    .join(",");
}

function sameConfig(preset: Preset, trace: Trace): boolean {
  return (
    preset.config.grant === trace.config.grant &&
    activeIds(preset.config.attacks) === activeIds(trace.config.attacks) &&
    activeIds(preset.config.capabilities) === activeIds(trace.config.capabilities)
  );
}
