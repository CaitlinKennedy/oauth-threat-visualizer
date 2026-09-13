// Exact TypeScript mirror of backend/otv/contract.py.
// Kept in lockstep with the Python dataclasses; SCHEMA_VERSION must match.
// This is the single seam between the backend and the UI: the UI is a pure
// function of a `Trace`.

export const SCHEMA_VERSION = "1.0";

export type Actor = "client" | "auth_server" | "resource_server" | "attacker";
export type Phase = "authorize" | "redirect" | "token" | "resource" | "introspect";
export type Outcome = "ok" | "blocked" | "attack_success" | "attack_blocked";
export type CheckResult = "PASS" | "FAIL";
export type Grant = "authorization_code" | "client_credentials" | "jwt_bearer";

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
  highlight: string[];
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
  http?: HttpExchange;
  check?: Check;
  knowledge_delta: Partial<Record<Actor, KnowledgeState>>;
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
  // Present only when the backend served a committed fixture as a fallback.
  _source?: "fallback";
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
