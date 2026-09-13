import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ApiError,
  fallbackTrace,
  fetchCatalog,
  fetchPresets,
  runCompare,
  runScenario,
} from "./api";
import type { Catalog, CompareResponse, Preset, Trace } from "./types/trace";
import { Diagram } from "./components/Diagram";
import { Timeline } from "./components/Timeline";
import { Controls } from "./components/Controls";
import { DrillDown } from "./components/DrillDown";
import { VerdictBanner } from "./components/VerdictBanner";
import { KnowledgePanel } from "./components/KnowledgePanel";
import { CatalogStrip } from "./components/CatalogStrip";
import { CompareBar } from "./components/CompareBar";

const AUTOPLAY_MS = 1600;

function prefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    window.matchMedia?.("(prefers-reduced-motion: reduce)").matches
  );
}

type Side = "baseline" | "variant";

export default function App() {
  const [presets, setPresets] = useState<Preset[]>([]);
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [trace, setTrace] = useState<Trace | null>(null);
  const [compare, setCompare] = useState<CompareResponse | null>(null);
  const [side, setSide] = useState<Side>("variant");
  const [activePresetId, setActivePresetId] = useState<string | null>(null);
  const [index, setIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [status, setStatus] = useState<string>("Loading…");

  // The UI is a pure function of ONE trace: in compare mode that's the selected
  // side of the diff, otherwise the single run.
  const shownTrace = compare ? compare[side] : trace;
  const events = shownTrace?.events ?? [];
  const current = events[index] ?? null;
  const divergenceSeq = compare?.divergences[0]?.seq ?? null;

  const loadPreset = useCallback(async (preset: Preset) => {
    setPlaying(false);
    setActivePresetId(preset.id);
    setIndex(0);
    setStatus(`Running: ${preset.name}…`);
    try {
      if (preset.mode === "compare" && preset.compare) {
        const resp = await runCompare(preset.compare.baseline, preset.compare.variant);
        setCompare(resp);
        setTrace(null);
        setSide("variant");
        setStatus("Compare loaded — flip PKCE to watch the runs diverge.");
      } else {
        const t = await runScenario(preset.config);
        setCompare(null);
        setTrace(t);
        setStatus(
          t._source === "fallback" ? "Loaded (fixture fallback)." : "Live run loaded.",
        );
      }
    } catch (err) {
      if (err instanceof ApiError) {
        // The server understood but declined (e.g. a not-yet-built preset → 501).
        // Keep whatever is on screen and surface the reason, rather than showing a
        // misleading fallback trace.
        setStatus(`${preset.name} is not available: ${err.message}`);
        return;
      }
      // Network/parse failure: fall back to the bundled golden trace so the app
      // still demos something correct.
      setCompare(null);
      setTrace(fallbackTrace());
      setStatus("Backend unreachable — showing bundled demo trace.");
    }
  }, []);

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

  // Keyboard stepping: arrows step, space toggles play, Home/End jump, and in
  // compare mode "p" flips PKCE.
  useEffect(() => {
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
      } else if ((e.key === "p" || e.key === "P") && compare) {
        e.preventDefault();
        setSideKeepStep(side === "variant" ? "baseline" : "variant");
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [next, prev, events.length, compare, side, setSideKeepStep]);

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
              className={`preset-btn ${activePresetId === p.id ? "preset-active" : ""}`}
              disabled={!p.available}
              title={p.available ? p.description : `${p.description} (coming soon)`}
              onClick={() => loadPreset(p)}
            >
              <span className="preset-flow">
                {p.mode === "compare" ? "Compare" : `Flow ${p.flow}`}
              </span>
              <span className="preset-name">{p.name}</span>
              {!p.available && <span className="preset-soon">soon</span>}
            </button>
          ))}
        </div>
      </header>

      {shownTrace && <VerdictBanner verdict={shownTrace.verdict} />}

      {compare && (
        <CompareBar
          compare={compare}
          side={side}
          onSetSide={setSideKeepStep}
          currentSeq={current?.seq ?? null}
        />
      )}

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
            divergenceSeq={divergenceSeq}
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
        {shownTrace && (
          <span className="corr">run {shownTrace.correlation_id.slice(0, 14)}…</span>
        )}
        <span className="hint">
          Keys: ← → step · space play/pause · Home/End jump
          {compare ? " · p flip PKCE" : ""}
        </span>
      </footer>
    </div>
  );
}
