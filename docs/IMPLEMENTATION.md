# OAuth Threat Visualizer — Implementation Plan

This is the build companion to [DESIGN.md](DESIGN.md). DESIGN.md holds the full vision;
this doc settles the stack, structure, the frozen trace/event contract, the scoped
first slice, and the build order.

## 1. Stack

| Layer | Choice | Why |
|---|---|---|
| Backend | **Python 3.11 + Flask** | Serves the API and the built UI from one process. OAuth endpoints are **hand-rolled on primitives** (not a framework) so every protocol step and check is ours to instrument, toggle, and expose. |
| Crypto | **`cryptography`** + **`PyJWT`** (JWS/JWT); `hashlib`/`base64` for PKCE; EC keys + JWK thumbprint (RFC 7638) for DPoP | Real S256 PKCE, real JWS signing/verification, real DPoP proofs, real key material. No mocking of the security-relevant parts. |
| Frontend | **React + TypeScript (Vite)** | The UI is a pure function of the trace; React state maps cleanly onto step/video playback and drill-down. |
| Transport | **One `POST /api/run` returns the fully materialized trace**; the UI plays it back client-side | Traces are finite and fully materialized, so streaming is unnecessary. This sidesteps Flask SSE awkwardness and makes step/scrub/video trivial and offline-capable. |
| Deploy | **Single container** (multi-stage: build React → Flask serves `static/` + API) via gunicorn | One deployable unit, one public URL, nothing for a user to install/build/compile. |

Recommended host: **Fly.io or Render** (single container, free/cheap tier, HTTPS out of
the box). Easily swapped — nothing depends on the host.

## 2. Repo structure

```
oauth-threat-visualizer/
├── docs/                       DESIGN.md, IMPLEMENTATION.md
├── backend/
│   ├── app.py                  Flask: /api/* + serves the built UI
│   ├── requirements.txt
│   ├── otv/
│   │   ├── contract.py         FROZEN event schema (dataclasses) + validator + SCHEMA_VERSION
│   │   ├── crypto.py           PKCE, JWS/JWT sign+verify, DPoP proofs, JWK thumbprints
│   │   ├── recorder.py         collects ordered, correlated events → a Trace
│   │   ├── actors/
│   │   │   ├── client.py       legit RP
│   │   │   ├── auth_server.py  authorize / token / jwks (enforces enabled capabilities)
│   │   │   ├── resource_server.py  validates tokens (+ DPoP/audience when on)
│   │   │   └── attacker.py     real attacks against the real actor APIs
│   │   ├── engine/
│   │   │   └── conductor.py    runs a scenario end-to-end → Trace + verdict
│   │   ├── scenarios.py        capability/attack configs + the flow presets
│   │   └── fixtures/           committed golden traces (scripted fallback / demo)
│   └── tests/                  contract validator + scenario snapshot tests
├── frontend/                   Vite React TS app
│   └── src/
│       ├── types/trace.ts      mirror of contract.py (kept in lockstep)
│       ├── api.ts
│       └── components/         Diagram, Timeline, DrillDown, VerdictBanner,
│                               KnowledgePanel, Controls, GlossaryTooltip
├── Dockerfile                  multi-stage build → single image
└── README.md                   standalone project readme (meta-free)
```

## 3. The frozen trace/event contract

Defined once in `contract.py`; `frontend/src/types/trace.ts` mirrors it exactly. A
`SCHEMA_VERSION` and a validator guard it. **Live runs and committed fixtures emit the
identical shape**, so the UI can't tell them apart.

```jsonc
// One run (a Trace):
{
  "schema_version": "1.0",
  "correlation_id": "run_...",
  "parent_id": null,                   // set when this trace is a stage of a chained
  "chain_id": null,                    //   attack (Phase 4); null for a standalone run.
                                        //   Reserved in v1.0 so chaining needs no schema change.
  "config": RunConfig,                 // see below — an OPEN id-keyed map, not fixed fields
  "verdict": { "attacker_got_token": false,
               "user_got_token": true,          // the honest user's outcome, always reported
               "user_accessed_resource": true,  //   (a run answers both lanes at once)
               "blocked_at_seq": 9,
               "responsible_capability": "pkce",         // primary blocker (headline)
               "responsible_capabilities": ["pkce", "state"], // all contributing blockers,
                                                              //   primary first; [] if none
               "one_line": "Attacker obtained an access token: NO — PKCE verifier mismatch." },
  "chain_verdict": null,               // set only on the terminal sub-trace of a chained
                                        //   attack: a roll-up across its linked stages
                                        //   ({attacker_got_token, responsible_capabilities,
                                        //    blocked_at:{trace_id, seq}}). null otherwise.
  "events": [ StepEvent, ... ]
}

// RunConfig — capabilities/attacks are OPEN id-keyed maps of STATE OBJECTS, never bare
// booleans and never fixed named fields. Adding a capability in a later phase is a new
// catalog entry + a new registry class — the wire schema does NOT change.
{
  "grant": "authorization_code",
  "capabilities": {
    "pkce":  { "active": true,  "params": { "method": "S256" } },
    "state": { "active": false }
    // ...only the ids the caller sets; unknown-but-catalogued ids default from the catalog
  },
  "attacks": {
    "auth_code_injection": { "active": true, "params": {} }
  }
}

// StepEvent:
{
  "seq": 9,
  "actor": "auth_server",              // client | auth_server | resource_server | attacker
  "on_behalf_of": "attacker",          // whose intent this action serves (superset of a
                                        // naive user|attacker "lane"; attacker may act
                                        // *through* the victim's browser)
  "phase": "token",                    // authorize | redirect | token | resource | introspect
  "refs": [2, 4],                      // seqs this event causally depends on
  "summary": "Token endpoint rejects the exchange.",
  "detail": "The client (here, the attacker) presents the stolen code, but ...",
  "http": {                            // exact request/response; decisive field flagged
    "request": { "method": "POST", "url": "/oauth/token",
                 "headers": {...}, "body": {"code": "...", "code_verifier": "..."} },
    "response": { "status": 400, "body": {"error": "invalid_grant"} },
    "highlight": ["code_verifier"]
  },
  "check": {                           // present only at mitigation points
    "name": "pkce_verifier_match",
    "rule": "S256(code_verifier) == code_challenge",
    "expected": "b3f...", "actual": "9a1...",
    "result": "FAIL",
    "spec_ref": { "rfc": "RFC 7636", "section": "§4.6" }
  },
  "knowledge_delta": {                 // what each actor now holds
    "attacker": { "has": ["code"], "lacks": ["code_verifier"] },
    "client":   { "has": ["code_verifier", "code_challenge"] }
  },
  "spec_refs": [ { "rfc": "RFC 6749", "section": "§4.1.3" } ],
  "outcome": "attack_blocked"          // ok | blocked | attack_success | attack_blocked
}
```

The `check`, `knowledge_delta`, and `verdict` fields are what turn "an HTTP 400" into the
flow-3 "aha". This contract is the stable seam that later lets the four internal actors
become four deployed servers with no UI change.

**Backend model behind the open wire-map.** The open id-keyed config is validated against
a **typed registry**: each capability and attack is a small self-documenting class
(id, label, description, spec ref, param schema, `default_active`, incompatibilities, the
phase it arrives in, and its enforcement/behaviour hook). The wire stays frozen; the
registry grows per phase. `GET /api/catalog` (see §5) is just this registry serialized, so
the UI picker is **data-driven**: adding a capability adds a catalog entry the picker
renders automatically, without a picker rewrite. The accurate invariant is that
**the wire contract is frozen; the UI grows additively, driven by catalog data** —
later phases still add *new* rendering (Phase 3 draws meta-capability lock state and
multi-divergence diffs; Phase 7 adds a second-AS node, a chain-stitched timeline, and
a multi-capability verdict banner), but they never break the contract or rewrite what
already exists.

**Paired diff (the flow-2↔3 gesture).** `POST /api/run` accepts an optional `compare`
block naming a baseline and a variant that differ by one toggle (e.g. `pkce.active`
false→true). The server runs both and returns both traces plus the computed **divergence**
(first differing `seq` and why), so the diff is authoritative and snapshot-testable
server-side rather than reconstructed in the client:

```jsonc
// POST /api/run  (compare form) → response
{ "mode": "compare",
  "baseline": Trace, "variant": Trace,
  // divergences is a LIST — one toggle can differ at more than one step (a check
  // and a downstream outcome). `divergence` is a convenience alias for the first.
  "divergences": [ { "seq": 9, "reason": "pkce_verifier_match", "capability": "pkce" } ],
  "divergence":  { "seq": 9, "reason": "pkce_verifier_match", "capability": "pkce" } }
```

**Chained attacks** are modeled as **linked sub-traces**: each stage is its own Trace
sharing a `chain_id`, with `parent_id` pointing at the prior stage. The UI stitches them
onto one timeline. Both fields exist in v1.0, so this needs no contract change.

**Meta-capabilities / bundling (e.g. OAuth 2.1).** A capability entry may declare
`implies: [ids]` (and `forbids: [ids]`). When a meta-capability is active, the registry
**forces its implied members active and locked** — the server resolves this authoritatively
during config validation, and the catalog exposes `implies`/`forbids` so the UI can render
the members as checked-and-disabled with a "required by OAuth 2.1" note (you can only free
them by turning the meta-capability off). `oauth_2_1` is exactly this: it implies `pkce`,
`redirect_uri_exact`, and `state`, and forbids the implicit grant — a single toggle that
*is* the modern posture. This is additive to the catalog schema; the wire contract and the
open config map are unchanged.

## 4. How each actor stays real

- **Client:** generates a real `code_verifier`/`code_challenge` (S256), builds real
  authorization requests, does the real back-channel token exchange, presents a real DPoP
  proof when enabled.
- **Auth server:** real authorization + token endpoints, a real single-use code store,
  real S256 verification, signs real JWT access tokens with a generated key (JWKS
  exposed), binds `cnf.jkt` for DPoP, emits `iss` when that capability is on. Each
  enforced check emits a `check` event.
- **Resource server:** validates the JWT signature/exp/aud and, when DPoP is on, the proof
  and key binding — the place a stolen bearer token visibly fails.
- **Attacker:** performs genuine attacks against the actor APIs (intercept a code, inject
  it into a victim session, replay a code/token, a phishing lure that harvests a
  detail). It only ever holds what it could realistically obtain — that's what
  `knowledge_delta` exposes.

`conductor.py` wires a scenario config → drives the actors → returns the Trace + verdict.
The **scripted fallback** is just a committed Trace of the same shape in `fixtures/`;
`/api/run` falls back to it if a live run raises, and the frontend also bundles fixtures
so a cold backend still demos.

## 5. API surface (control plane)

| Endpoint | Purpose |
|---|---|
| `GET /api/catalog` | The typed registry serialized: every capability + attack with id, label, description, spec ref, `default_active`, param schema, `applies_to_grants`, `implies`, `forbids`, `incompatibilities`, phase. **The picker renders from this**: adding a capability adds a catalog entry the picker shows automatically. The wire contract is frozen; the UI grows *additively* from catalog data (a new capability may still bring new rendering, but never a contract change). |
| `GET /api/scenarios` | Named presets that map to the learning flows (each preset is a ready-made `RunConfig`). |
| `POST /api/run` | Body = a `RunConfig` (§3); returns the materialized Trace. With an optional `compare` block, returns `{baseline, variant, divergence}` (§3). |
| `GET /api/fixtures/<id>` | A committed golden trace (demo / fallback). |
| `GET /api/health` | Liveness. |
| `GET /*` | Serves the built React app. |

### 5a. Actor architecture — the interface/impl seam

Each actor is exposed to the rest of the backend as a **documented "service API" class**:
an interface (`typing.Protocol` or `abc.ABC`) whose public methods are named for the
actor's future REST actions (e.g. `AuthServer.authorize(...)`, `.token(...)`, `.jwks()`;
`ResourceServer.get_resource(...)`), each with a clear docstring stating its contract.
A concrete `*Impl` class hides all internal detail. **Callers depend only on the
interface.** In Phase 0 these are ordinary in-process calls; promoting the four actors to
four standalone servers later is then an implementation/transport swap (a REST client that
satisfies the same interface) with no change to callers, the trace contract, or the UI.
(This is the Python equivalent of a Java interface + Javadoc + hidden impl.)

## 6. Phased delivery

Each phase ships on its **own feature branch with its own PR** (see §10). Phases are
ordered so the vertical slice exists first, then the pedagogical payoff, then breadth.

### Phase 0 — scaffold + OAuth 2.0 Authorization Code (happy path)

The foundational vertical slice. Delivers **flow 1 only** (a clean authorization-code run,
no attack) end to end:

- Repo scaffold per §2; the **frozen contract** (`contract.py` + `types/trace.ts`) +
  validator; `crypto.py` (key generation, JWS sign/verify — PKCE deferred to Phase 1).
- Actors: **client**, **auth server** (authorize/token/jwks, single-use code store),
  **resource server** (validate JWT + serve a protected resource). Attacker actor present
  but idle (node shown, no actions yet).
- `conductor.py` + `scenarios.py` for the happy-path preset; `POST /api/run` +
  `GET /api/scenarios` + `GET /api/health`.
- UI essentials: 4-node **diagram** with active highlighting, **timeline** with
  step/prev/next + one-click **video mode**, four-depth **drill-down**, **verdict banner**
  ("user obtained a token: YES"), **actor-knowledge panel**, glossary tooltips, keyboard
  stepping, `prefers-reduced-motion`, pass/fail not by color alone.
- One committed **fixture** for the happy path; **Dockerfile** + deploy; app boots in
  demo mode with the happy-path flow ready to Play.

This must exist and be deployable before anything else — it proves the whole contract →
actors → trace → UI pipeline with the simplest possible flow.

### Phase 1 — PKCE + auth-code injection (the flow-3 "aha")

Builds on Phase 0 to deliver **flows 2 and 3**:

- **PKCE** capability (real S256 verifier/challenge) with a first-class `check` event.
- **Attacker** actor made real: **auth-code injection** against the live endpoints.
- Three runs from one toggle: injection with **PKCE off** (attacker wins) vs **PKCE on**
  (same attack fails at the verifier `check`), plus the happy path from Phase 0.
- The **flow-2↔3 diff toggle** as the primary gesture; verdict banner shows the
  responsible capability; knowledge panel shows "attacker has `code`, lacks
  `code_verifier`". Fixtures for both attack runs.

## 7. Build order after Phase 1

The through-line is the thesis **every mitigation is a binding**; each phase adds a binding
(or shows one being removed) and the attack it closes.

> **Scope note.** This build ships Phases 0–2 and 4–6. **Phase 3 (OAuth 2.0 vs 2.1,
> incl. the `oauth_2_1` meta-capability) and Phase 7 (combined-attack capstone) are
> DEFERRED / out of scope for this build** — they are retained below as design intent,
> not as shipped features.

- **Phase 2 — `state`/CSRF + auth-code replay.** `state` binds the response to the user's
  session (RFC 6749 §10.12); a real single-use code store makes a **replayed code** fail
  the second time (RFC 6749 §4.1.2; RFC 9700). Two mitigations composing in one open
  config map; catalog now serves several capabilities (validates the data-driven picker).

- **Phase 3 — OAuth 2.0 vs 2.1, formally.** Adds two *individual* items: capability
  **exact `redirect_uri` matching** vs 2.0's loose match, and attack **redirect-URI
  manipulation / open-redirect code leak** (RFC 9700 §4.1). Introduces the **`oauth_2_1`
  meta-capability** (§3 bundling): selecting it auto-selects and **locks** `pkce`,
  `redirect_uri_exact`, and `state` (and forbids implicit) — UI shows them checked+disabled
  as "required by OAuth 2.1". The lesson runs the same attacks under a **2.0-defaults vs
  2.1-defaults paired diff**. Binding: exact match binds the response to the client's
  registered endpoint.

- **Phase 4 — JWT bearer *grant* vs auth code.** The JWT *authorization grant*
  (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, RFC 7523): a signed assertion
  stands in for the user (`sub`), so a user-scoped token is obtained with **no browser,
  redirect, or consent** — sidestepping the entire front-channel attack surface (code
  interception/injection, redirect CSRF, mix-up). Counter-lesson (the honest tradeoff): the
  trust **relocates to the signing key + assertion**; the new attack is **assertion replay**,
  mitigated by `jti` + short `exp` + `aud`=token endpoint. Binding: identity ↦ key + audience
  + time window instead of a live login. (Distinct from Phase 5 — this is a *grant type*.)

- **Phase 5 — client credentials + client authentication methods.** The client-credentials
  grant (RFC 6749 §4.4) where **the client itself is the principal** (no user) — the M2M vs
  user-based contrast. Compares client-auth methods: `client_secret_basic` (Basic header) vs
  `client_secret_post` (body) vs **`private_key_jwt`** (`client_assertion`, RFC 7523 §2.2).
  Attack: **static-secret leak** (a never-rotating secret = permanent impersonation) defeated
  by the key-based assertion (AS holds only the public key; assertions short-lived +
  `jti`-protected). These client-auth methods are orthogonal to the grant and apply to auth
  code too. Binding: client identity ↦ key vs a shared static secret. (mTLS / `tls_client_auth`,
  RFC 8705, noted as further reading.)

- **Phase 6 — DPoP vs token replay.** Sender-constrained tokens via a proof-of-possession
  key + `cnf.jkt` binding (RFC 9449). Cleanest single-toggle aha: a stolen **bearer** token
  works anywhere, a **DPoP-bound** token dies at the **resource server** without the matching
  key. Binding: token ↦ client key (the token-level sibling of Phase 5's key-vs-secret).

- **Phase 7 — combined-attack capstone.** A longer **chained** attack (linked sub-traces via
  `parent_id`/`chain_id`) that the layered bindings defeat together: introduces **AS issuer
  identification** (RFC 9207) and the **mix-up attack** (RFC 9700 §4.4), combined with
  phishing → code injection. The payoff of the thesis — the attacker must satisfy several
  bindings at once (issuer↦AS, code↦client via PKCE, response↦session via state) and cannot.

- **Stretch —** promote the four internal actors to four independently deployed servers
  (separate origins, cross-service HTTP) — contract unchanged; PAR; refresh-token rotation;
  mTLS / certificate-bound tokens.

## 8. Testing

- **Contract validator** over every emitted trace (`test_contract.py`) — schema + version.
- **Scenario snapshots** (`test_scenarios.py`): each preset's verdict and its
  `blocked_at_seq`/`responsible_capability` are asserted, so a regression that lets an
  attack "succeed" fails CI. This is also how fixtures are regenerated.
- A shared **golden trace** doubles as a frontend render test.

## 9. Deployment

Multi-stage Dockerfile: build the Vite app, copy `dist/` into the Flask image's static
dir, run gunicorn. The app boots in **demo mode** by default (a preset flow ready to Play
on load) so the very first interaction is a runnable flow, not an empty form.

## 10. Branch & PR workflow

- Each phase is developed on its **own feature branch** off `main`, named
  `phase-<n>-<slug>` (e.g. `phase-0-oauth2-auth-code`, `phase-1-pkce-injection`).
- Every phase lands via a **pull request** into `main`, so changes are reviewable per
  phase rather than in one large drop.
- Branches are kept small and focused on their phase's scope.
