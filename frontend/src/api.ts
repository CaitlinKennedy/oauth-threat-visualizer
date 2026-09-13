// The only place the UI talks to the backend. Everything else consumes a
// `Trace`, regardless of whether it came from a live run, a fixture endpoint,
// or the bundled fallback — the contract makes them indistinguishable.

import type { Catalog, PresetsPayload, ScenarioConfig, Trace } from "./types/trace";
import happyPathFixture from "./fixtures/happyPath.json";

const bundledFallback = happyPathFixture as unknown as Trace;

async function getJSON<T>(url: string): Promise<T> {
  const res = await fetch(url, { headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return (await res.json()) as T;
}

// Named presets → the learning flows.
export async function fetchPresets(): Promise<PresetsPayload> {
  return getJSON<PresetsPayload>("/api/scenarios");
}

// The typed registry → the data-driven capability/attack picker (roadmap in P0).
export async function fetchCatalog(): Promise<Catalog> {
  return getJSON<Catalog>("/api/catalog");
}

export async function runScenario(config: ScenarioConfig): Promise<Trace> {
  const res = await fetch("/api/run", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ config }),
  });
  if (!res.ok) throw new Error(`/api/run -> ${res.status}`);
  return (await res.json()) as Trace;
}

// Used on cold boot / offline: the bundled golden trace so the app always has
// something correct to play even if the backend is unreachable.
export function fallbackTrace(): Trace {
  return { ...bundledFallback, _source: "fallback" };
}
