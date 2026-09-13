# OAuth Threat Visualizer — Design

## 1. Overview

OAuth 2.0/2.1 is widely deployed and widely misunderstood. Its security is *emergent*:
whether an attacker wins depends on subtle interactions between many optional features.
The RFCs explain the pieces, not the dynamics — and almost never the adversary's view.

The OAuth Threat Visualizer is an interactive explainer. A user selects which OAuth
capabilities are enabled and which attacks are attempted, then watches a real,
instrumented exchange play out across four actors — as *both* the legitimate user and the
attacker experience it — drilling from a one-line summary down to exact HTTP messages and
the specific RFC clauses that govern them.

**A unifying thesis: every mitigation is a *binding*.** PKCE binds the authorization code
to the client instance that began the flow; `state` binds the response to the user's
session; the authorization server's `iss` binds the response to the AS that issued it;
DPoP binds the token to a client-held key; a JWT assertion binds client identity to a
short-lived signed proof instead of a static secret. Every attack is an attempt to use
something whose binding the attacker cannot satisfy. The tool is built to make that one
idea visible: *what does the attacker need, what is each artifact bound to, and which
binding does the attacker lack?*

**Design principles**

- *Real over simulated.* Genuine OAuth: real PKCE verifiers, real JWT signing and
  verification, real DPoP proofs, real single-use-code enforcement. Mitigations work
  because the protocol works, not because a script says so.
- *The adversary is a first-class actor* with its own service and, where relevant, its
  own origin.
- *Progressive disclosure.* Every step is legible at four depths.
- *Self-contained.* Bundled scenarios and a demo mode: a user needs only a URL.

## 2. Audience & the four learning flows

1. **Capability only, no attack** — "how does OAuth actually work?" A clean happy-path run
   that establishes the mental model and vocabulary.
2. **Capability + attack (no mitigation)** — "what does the attacker see and do?" The
   attack succeeds; the user watches how and why from the adversary's lane.
3. **Capability + mitigation + attack** — "why is this mitigation required?" The identical
   attack now *fails* at a specific highlighted step. The core payoff; it grounds why
   OAuth 2.1 makes PKCE mandatory. The primary gesture is to toggle the mitigation and
   watch flow 2 and flow 3 diverge at one step.
4. **Pacing** — step-by-step at the reader's pace, or one-click auto "video mode".

## 3. System architecture

One deployable backend service composed of **separate internal actor services** behind a
shared, **frozen trace/event contract**. The UI is a pure function of that trace.

```
        ┌────────────────────────────────────────────────────────┐
        │                    Visualizer UI                         │
        │  scenario picker · component diagram · drill-down ·      │
        │  dual-lane (user / attacker) · step & video playback     │
        └───────────────▲───────────────────────▲─────────────────┘
                        │ trace/event stream     │ control (run/step/toggle)
        ┌───────────────┴────────────────────────┴────────────────┐
        │        Backend service  (one deployable unit)            │
        │  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌─────────┐  │
        │  │  Client  │  │ IdP / Auth│  │ Resource │  │ Attacker│  │
        │  │ (RP)     │  │  Server   │  │  Server  │  │ client  │  │
        │  └──────────┘  └───────────┘  └──────────┘  └─────────┘  │
        │        internal actor APIs — real OAuth logic            │
        │  ─────────── Trace / Event Bus (frozen contract) ─────── │
        └──────────────────────────────────────────────────────────┘
```

- **Client (legitimate relying party).** Initiates flows, holds and uses tokens, calls the
  resource server; configured per capability.
- **IdP / Authorization Server.** Login and consent, authorization/token/JWKS/(optional
  introspection, PAR) endpoints; enforces the enabled capabilities.
- **Resource Server.** Protects an API; validates tokens (plus DPoP binding and audience
  when enabled). This is where a stolen-but-unbound token visibly fails.
- **Attacker client.** Runs real attacks against the real endpoints (intercept/replay a
  code, inject a code into a victim session, phishing/smishing lure, and chained
  variants). Modeled as its own actor with its own origin where it matters.
- **Trace / Event Bus.** Every actor emits structured, correlated step events (§7). This
  is the contract the UI renders and is what makes the system visualizable.

**Contract-first stretch path.** Because the trace contract and the internal actor APIs
are defined up front and stable, promoting the four internal actors into four
independently deployed servers (separate origins, cross-service HTTP) is a **stretch
goal** that requires no change to the UI or the contract.

**Deployment.** The single service deploys to a host behind one public URL, so it can be
used immediately in a browser with nothing to install, build, or compile, while the flows
remain genuinely live.

## 4. OAuth capability catalog (configurable feature flags)

Capabilities exist to (a) defeat an attack, (b) *contrast* with a weaker alternative, or
(c) provide standalone *basis* understanding. The capability and attack lists need not map
1:1.

| Capability | One-liner | Teaching role | Spec |
|---|---|---|---|
| **Authorization Code grant** | redirect → code → back-channel token exchange | basis; the canvas most attacks target | RFC 6749 §4.1 |
| **PKCE** | code bound to a per-request verifier | defeats code interception/injection; mandatory in 2.1 | RFC 7636 |
| **`state` parameter** | response bound to the user's session | defeats CSRF / cross-session injection | RFC 6749 §10.12 |
| **Client Credentials grant** | machine-to-machine; static `client_id`+`secret` | basis + **contrast**: a secret that never rotates is easy to exploit once leaked | RFC 6749 §4.4 |
| **JWT Bearer grant** | exchange a short-lived signed assertion for a token | **contrast** with static secret: key-based, short-lived, non-replayable | RFC 7523 |
| **DPoP** | sender-constrained tokens via a proof-of-possession key | defeats token theft/replay (bearer → bound) | RFC 9449 |
| **AS Issuer Identification** | AS returns its `iss` in the authorization response | defeats IdP mix-up | RFC 9207 |
| **OAuth 2.1 posture** | composite preset: auth code + PKCE mandatory, no implicit | aggregates the above into "the modern default" | OAuth 2.1 draft |

## 5. Attack catalog

Attacks can be atomic or **chained**. Each: mechanism, what it threatens, what defeats it.

| Attack | Mechanism | Threatens | Defeated / weakened by | Reference |
|---|---|---|---|---|
| **Auth-code injection** | inject an attacker-obtained code into a victim's session | auth code flow | **PKCE** (verifier mismatch), **`state`** | RFC 9700 §4.5; RFC 7636 |
| **Auth-code / token replay** | reuse a captured code or token a second time | code & resource endpoints | one-time codes (code); **DPoP** (token) | RFC 9700; RFC 6819 |
| **Phishing / smishing** | fake login/consent via email/SMS lure harvests creds or a code | the user, front channel | user-education + binding; feeds downstream injection/replay | RFC 6819; RFC 9700 |
| **Static-secret leak** | a never-rotating `client_id`+`secret` is captured and reused | client-credentials clients | **JWT assertion** (short-lived, key-bound) | RFC 6749 §10; RFC 7523 |
| **Chained: phish → inject** | phishing harvests a detail that enables auth-code injection | end-to-end | **PKCE**/`state` still break the final redemption | RFC 9700 |

## 6. Capability × attack interaction (the pedagogical core)

For each (capability set, attack) the run produces an observable **succeeds /
fails-at-step-N** outcome — *emitted by the real protocol*, not a hard-coded verdict.
Illustrative:

| Attack \ Capability | Bare auth code | + PKCE | + `state` | + DPoP |
|---|---|---|---|---|
| Code injection | **succeeds** | **fails** (verifier mismatch at token endpoint) | **fails** (session mismatch) | — |
| Code/token replay | **succeeds** | partial | — | **fails** (proof/key mismatch at RS) |

## 7. Instrumentation & the frozen trace contract

The most important internal abstraction; defined once and never changed (this is what
makes the four-server split a safe stretch). Every actor emits ordered, correlated **step
events**:

- `schema_version`, `correlation_id`, `seq`, `actor`, `intent`/`on_behalf_of`
  (a superset of a naive user|attacker "lane" — in code injection the attacker acts
  *through* the victim's browser), `phase` (enum: `authorize` · `redirect` · `token` ·
  `resource` · `introspect`), `refs: [seq]` (causality — which earlier events this one
  depends on).
- **Layered description**: `summary` (one line) → `detail` (paragraph) → `http` (method,
  URL, headers, body — exact, with the *decisive* parameter flagged for highlighting) →
  `spec_refs` (RFC + exact section pointer).
- A first-class **`check` event** for mitigation points: what was checked, `expected` vs.
  `actual`, `PASS|FAIL`, and the spec clause that *mandates* the check (e.g.
  `S256(code_verifier) == code_challenge`, RFC 7636 §4.6).
- An **actor-knowledge ledger** delta: what each actor now holds (e.g. the client has
  `code_verifier`; the attacker has `code` but *not* `code_verifier`).
- `outcome` (`ok` | `blocked` | `attack_success` | `attack_blocked` | `partial`) with the
  responsible capability when blocked (`partial` covers a downgraded win, e.g. replay under
  PKCE — DESIGN §6).
- A run-level **`verdict`** answering both lanes at once: `attacker_got_token`,
  `user_got_token`, `user_accessed_resource`, a one-line summary, and — when an attack is
  blocked — `blocked_at_seq`, the primary `responsible_capability`, and the full
  `responsible_capabilities` list (multiple bindings can compose). A chained attack adds a
  `chain_verdict` roll-up on its terminal sub-trace (`attacker_got_token`,
  `responsible_capabilities`, and where it was `blocked_at`).

A tiny **golden-trace validator** guards the schema. Live runs and the scripted fallback
emit the *same* contract, so the UI cannot tell them apart.

## 8. Visualizer UX

- **Land the user in flow 3** with a Play button and a one-sentence "why care" — not an
  empty config picker. The scenario matrix is offered *after* the first aha.
- **Component diagram** — four actors as nodes, messages as arrows; the active node/edge
  highlights as the flow advances (respecting `prefers-reduced-motion`).
- **Flow-2↔3 diff toggle** — the primary gesture: flip a mitigation and watch the two runs
  stay identical until they diverge at one highlighted step.
- **Drill-down** — click any step or edge to descend the four depths (§7).
- **Dual-lane view** — user and attacker on a shared timeline, so it is obvious what the
  attacker does *while* the user does something innocuous.
- **Actor-knowledge panel** — "what the attacker has vs. needs" beside the diagram.
- **Verdict banner** — "Attacker obtained an access token: YES/NO — because …" in one
  sentence before any drill-down.
- **Playback** — step (Next/Prev, scrub) or one-click video mode.
- **Glossary tooltips** for `code_challenge`, `redirect_uri`, `bearer`, and similar;
  pass/fail is never conveyed by color alone; keyboard step-through is supported.
- The visual design of this view was iterated after the first build (landing screen,
  collapsed command bar, two-column stage, "Paper & ink" palette); the trace-driven
  behavior above is unchanged.

## 9. Demo mode & self-containment

Bundled scenarios per learning flow, requiring zero input. Live runs are primary; a
**scripted fallback** (same §7 contract) plays a captured canonical trace if a live step
is unavailable, so the user always sees a complete, correct flow.

## 10. Non-goals

Not a general-purpose IdP or a drop-in auth library; not exhaustive coverage of every
grant and attack; no real PII (the "victim" is a synthetic bundled account); attacks are
confined to the sandboxed service and cannot reach anything external.

## 11. Security & ethics

Every attack runs only against the tool's own contained actors — there are no controls to
target third parties, no off-box exfiltration, and phishing pages are clearly sandboxed.
The intent is defensive understanding: showing *why* mitigations exist.

## 12. Open questions (for implementation planning)

- Per-actor technology, and how the trace bus is realized (SSE/WebSocket vs. polling a
  store).
- Priority order of capability × attack combos; how much of the OAuth 2.1 composite to
  model vs. compose from individual flags; the exact hosting target.
