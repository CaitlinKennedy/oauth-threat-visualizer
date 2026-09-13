# OAuth Threat Visualizer

An interactive explainer for OAuth 2.0 / 2.1. It runs a **real, instrumented**
OAuth exchange across four actors — client, authorization server, resource
server, and attacker — and lets you drill from a one-line summary of each step
down to the exact HTTP message and the RFC clause that governs it.

OAuth's security is *emergent*: whether an attacker wins depends on subtle
interactions between optional features. The unifying idea this tool makes visible
is that **every mitigation is a binding** — PKCE binds the code to the client
instance, `state` binds the response to the session, and so on — and every attack
is an attempt to use something whose binding the attacker cannot satisfy.

> This is the first vertical slice: the clean OAuth 2.0 **Authorization Code**
> happy path, end to end. Later phases add capabilities (PKCE, `state`, DPoP, …)
> and real attacks (auth-code injection, replay, phishing chains) so you can
> toggle a mitigation and watch the same attack fail at one highlighted step.

## What you can do today

- Watch the authorization-code flow play out step by step, or in one-click
  "video" mode.
- Drill into any step at four depths: **summary → detail → exact HTTP → spec
  reference**.
- See the **actor-knowledge ledger** — what each actor holds at each moment.
- Read the **verdict**: did the user obtain a token and reach the API, and did
  any attacker obtain a token?

The tokens are genuine: the authorization server signs real RS256 JWT access
tokens with a generated key and publishes a JWKS; the resource server really
verifies the signature, expiry, issuer, and audience before serving the resource;
authorization codes are single-use and enforced as such.

## Architecture

One deployable backend service composed of **separate internal actor services**
behind a **frozen trace/event contract**. The UI is a pure function of the trace
a run produces.

```
  React + TypeScript UI  ── renders ──▶  Trace (frozen contract)
          ▲                                     ▲
          │ POST /api/run                        │ emitted by
          │                                       │
  Flask backend ──▶ conductor ──▶ [ client · auth server · resource server · attacker ]
                                   real, hand-rolled OAuth on cryptographic primitives
```

- **Frozen contract** (`backend/otv/contract.py`, mirrored in
  `frontend/src/types/trace.ts`): every actor emits ordered, correlated step
  events — `summary`/`detail`/`http`/`spec_refs`, a first-class `check` at
  mitigation points, a per-actor `knowledge_delta`, and an `outcome`. A
  `SCHEMA_VERSION` and a validator guard the shape. Live runs and committed
  fixtures emit the identical shape, so the UI cannot tell them apart.
- **Actors** (`backend/otv/actors/`): each is exposed as a documented service-API
  interface (`AuthServer.authorize/.token/.jwks`, `ResourceServer.get_resource`,
  `Client.start_authorization/.exchange_code/.access_resource`), with a hidden
  `*Impl`. Callers depend only on the interfaces, so promoting any actor to a
  standalone service later is a transport swap — the contract and UI don't change.
- **Config & catalog**: capabilities and attacks travel as an open, id-keyed map
  of state objects, backed by a typed registry served at `GET /api/catalog`, so
  the picker is data-driven and the wire schema stays frozen as features are added.

### Backend layout

```
backend/
  app.py                Flask: the API + serves the built UI
  otv/
    contract.py         frozen event schema + validator + SCHEMA_VERSION
    crypto.py           key generation, JWS sign/verify (JWKS)
    recorder.py         collects ordered, correlated events → a Trace
    registry.py         typed capability/attack catalog (→ GET /api/catalog)
    scenarios.py        the learning-flow presets (→ GET /api/scenarios)
    actors/             client, auth_server, resource_server, attacker (+ environment)
    engine/conductor.py runs a scenario end-to-end → Trace + verdict
    fixtures/           committed golden trace (demo / fallback)
  tests/                contract-validator + scenario-snapshot tests (pytest)
```

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | Liveness. |
| `GET /api/catalog` | The typed capability/attack registry (data-driven picker). |
| `GET /api/scenarios` | Named presets mapping to the learning flows. |
| `POST /api/run` | Body is a run config; returns the fully materialized trace. |
| `GET /api/fixtures/<id>` | A committed golden trace (demo / fallback). |
| `GET /*` | Serves the built UI. |

## Run it locally with Docker

```bash
docker build -t oauth-threat-visualizer .
docker run --rm -p 8000:8000 oauth-threat-visualizer
# open http://localhost:8000
```

The app boots in **demo mode** with the happy-path flow loaded and ready to Play.

## Develop

Backend:

```bash
cd backend
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python app.py            # http://localhost:8000
pytest                   # run the tests
```

Frontend (Vite dev server, proxies `/api` to the backend on :8000):

```bash
cd frontend
npm install
npm run dev              # http://localhost:5173
npm run build           # production build → dist/
```

## Accessibility

Keyboard stepping (`←`/`→`, space to play/pause, `Home`/`End`), `prefers-reduced-motion`
is respected, and pass/fail is never conveyed by color alone (every verdict and
check also carries an icon and a text label).
