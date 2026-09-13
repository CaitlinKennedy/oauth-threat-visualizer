// Exact TypeScript mirror of backend/otv/contract.py.
// Kept in lockstep with the Python dataclasses; SCHEMA_VERSION must match.
// This is the single seam between the backend and the UI: the UI is a pure
// function of a `Trace`.

export const SCHEMA_VERSION = "1.0";

// Runtime enum tuples — the single source the type unions derive from, and what
// the cross-language guard test compares against backend/otv/contract_enums.json.
// Keep these byte-aligned with the tuples in contract.py.
export const ACTORS = [
  "client",
  "auth_server",
  "resource_server",
  "attacker",
] as const;
export const PHASES = [
  "authorize",
  "redirect",
  "token",
  "resource",
  "introspect",
] as const;
export const OUTCOMES = [
  "ok",
  "blocked",
  "attack_success",
  "attack_blocked",
  "partial",
] as const;
export const CHECK_RESULTS = ["PASS", "FAIL"] as const;
export const GRANTS = [
  "authorization_code",
  "client_credentials",
  "jwt_bearer",
  "implicit",
] as const;

export type Actor = (typeof ACTORS)[number];
export type Phase = (typeof PHASES)[number];
export type Outcome = (typeof OUTCOMES)[number];
export type CheckResult = (typeof CHECK_RESULTS)[number];
export type Grant = (typeof GRANTS)[number];

export interface SpecRef {
  rfc: string;
  section: string;
}

export interface HttpMessage {
  method?: string;
  url?: string;
  status?: number;
  headers?: Record<string, unknown>;
  body?: unknown;
}

export interface HttpExchange {
  request: HttpMessage;
  response: HttpMessage;
  // Dotted paths flagging the decisive field(s): `<side>.<section>.<key>` where
  // side is request|response and section is headers|body|query — e.g.
  // "request.headers.Authorization", "request.body.client_secret". Consumers
  // that don't parse the path can fall back to the trailing <key> segment.
  highlight: string[];
  // Explicit message direction so the diagram is a pure function of the trace (no
  // hostname string-matching). Each is one of Actor, or null/absent for an
  // actor-internal step with no cross-actor edge. *_instance disambiguates two
  // instances of one role (e.g. a mix-up scenario); absent for single-instance.
  source_actor?: Actor | null;
  target_actor?: Actor | null;
  source_instance?: string | null;
  target_instance?: string | null;
}

export interface Check {
  name: string;
  rule: string;
  result: CheckResult;
  spec_ref: SpecRef;
  expected?: string;
  actual?: string;
}

export interface KnowledgeState {
  has: string[];
  lacks: string[];
}

export interface StepEvent {
  seq: number;
  actor: Actor;
  on_behalf_of: string;
  phase: Phase;
  summary: string;
  detail: string;
  outcome: Outcome;
  refs: number[];
  // Distinguishes two instances of the same role in one run (e.g. an "honest" vs.
  // "rogue" auth server) without growing the ACTORS enum; absent for single-
  // instance runs.
  actor_instance?: string | null;
  http?: HttpExchange;
  check?: Check;
  // Keys are a bare actor ("attacker") or instance-qualified "actor#instance"
  // (e.g. "auth_server#rogue"); the actor part is always one of ACTORS.
  knowledge_delta: Record<string, KnowledgeState>;
  spec_refs: SpecRef[];
}

// The on-the-wire state of one capability or attack. Capabilities and attacks
// are OPEN id-keyed maps of these, never bare booleans or fixed fields, so the
// wire schema is frozen as features are added.
export interface FeatureState {
  active: boolean;
  params?: Record<string, unknown>;
}

export interface ScenarioConfig {
  grant: Grant;
  capabilities: Record<string, FeatureState>;
  attacks: Record<string, FeatureState>;
}

export interface Verdict {
  attacker_got_token: boolean;
  user_got_token: boolean;
  user_accessed_resource: boolean;
  one_line: string;
  blocked_at_seq?: number | null;
  responsible_capability?: string | null;
  // All contributing blockers, primary first (mirrors responsible_capability as
  // the headline). Empty when nothing blocked.
  responsible_capabilities?: string[];
}

// Where in a chained attack the block occurred (a specific sub-trace step).
export interface ChainBlock {
  trace_id: string;
  seq: number;
}

// Roll-up verdict across the linked sub-traces of one chained attack; carried on
// the terminal sub-trace (Trace.chain_verdict).
export interface ChainVerdict {
  attacker_got_token: boolean;
  responsible_capabilities?: string[];
  blocked_at?: ChainBlock | null;
}

export interface Trace {
  schema_version: string;
  correlation_id: string;
  config: ScenarioConfig;
  verdict: Verdict;
  events: StepEvent[];
  // Reserved for Phase 4 chained attacks (linked sub-traces); null otherwise.
  parent_id?: string | null;
  chain_id?: string | null;
  // Set only on the terminal sub-trace of a chain; null for a standalone run.
  chain_verdict?: ChainVerdict | null;
  // Present only when the backend served a committed fixture as a fallback.
  _source?: "fallback";
}

// --- Compare / diff response (the flow-2 vs flow-3 gesture) -----------------
// The SHAPE is frozen in v1.0; the compare logic (running baseline + variant and
// computing where they diverge) arrives in a later phase.

export interface Divergence {
  seq: number;
  reason: string;
  capability: string;
}

export interface CompareResponse {
  mode: "compare";
  baseline: Trace;
  variant: Trace;
  // A LIST — a single toggle can differ at more than one step. `divergence` is a
  // convenience alias for divergences[0].
  divergences: Divergence[];
  divergence?: Divergence;
}

// --- Presets (GET /api/scenarios) ------------------------------------------

export interface Preset {
  id: string;
  flow: number;
  name: string;
  tagline: string;
  description: string;
  config: ScenarioConfig;
  available: boolean;
  // Preset metadata (not part of the frozen trace contract). A preset with
  // `mode: "compare"` drives the paired-diff endpoint using `compare.baseline`
  // and `compare.variant` — the flow-2↔3 gesture.
  mode?: "compare";
  compare?: { baseline: ScenarioConfig; variant: ScenarioConfig };
}

export interface PresetsPayload {
  presets: Preset[];
  default_preset: string;
}

// --- Catalog / typed registry (GET /api/catalog) ---------------------------
// The picker renders from this, so the UI never changes when a feature is added.

export interface ParamSpec {
  name: string;
  type: string;
  default: unknown;
  description: string;
  choices?: string[];
}

export interface RegistryItem {
  id: string;
  label: string;
  description: string;
  spec_ref: SpecRef;
  kind: "capability" | "attack";
  phase: number;
  default_active: boolean;
  params: ParamSpec[];
  incompatibilities: string[];
  // Grant ids this item applies to; empty means all grants.
  applies_to_grants: string[];
  // Meta-capability bundling: ids this item forces active+locked (implies) or
  // disallows (forbids). A forbids entry may name a capability id OR a grant id
  // (e.g. oauth_2_1 forbids "implicit"). Both empty for a plain item.
  implies: string[];
  forbids: string[];
  // Names of the first-class checks (StepEvent.check.name) this item's own
  // enforcement emits, e.g. ["pkce_verifier_match"]. Empty for an item that
  // emits no first-class check (e.g. an attack).
  check_names: string[];
  available: boolean;
}

export interface Catalog {
  capabilities: RegistryItem[];
  attacks: RegistryItem[];
}

export const ACTOR_LABELS: Record<Actor, string> = {
  client: "Client (RP)",
  auth_server: "Authorization Server",
  resource_server: "Resource Server",
  attacker: "Attacker",
};
