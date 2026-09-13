// The only place the UI talks to the backend. Everything else consumes a
// `Trace`, regardless of whether it came from a live run, a fixture endpoint,
// or the bundled fallback — the contract makes them indistinguishable.

import type {
  Catalog,
  CompareResponse,
  PresetsPayload,
  ScenarioConfig,
  Trace,
} from "./types/trace";
import happyPathFixture from "./fixtures/happyPath.json";

const bundledFallback = happyPathFixture as unknown as Trace;

// A run/compare request the server understood but declined (e.g. a not-yet-built
// preset returns 501). Distinct from a network failure so the UI can show the
// server's message instead of a misleading fallback trace.
export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function getJSON<T>(url: string): Promise<T> {
  const res = await fetch(url, { headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return (await res.json()) as T;
}

async function postRun<T>(body: unknown): Promise<T> {
  const res = await fetch("/api/run", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
  });
  const json = (await res.json().catch(() => null)) as
    | (T & { message?: string; error?: string })
    | null;
  if (!res.ok) {
    const msg = json?.message || json?.error || `run failed (${res.status})`;
    throw new ApiError(res.status, msg);
  }
  return json as T;
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
  return postRun<Trace>({ config });
}

// The paired-diff (flow-2↔3) run: two configs differing by one toggle.
export async function runCompare(
  baseline: ScenarioConfig,
  variant: ScenarioConfig,
): Promise<CompareResponse> {
  return postRun<CompareResponse>({ compare: { baseline, variant } });
}

// Used on cold boot / offline: the bundled golden trace so the app always has
// something correct to play even if the backend is unreachable.
export function fallbackTrace(): Trace {
  return { ...bundledFallback, _source: "fallback" };
}
