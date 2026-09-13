# Deployment

The app is one container: a multi-stage build that compiles the React UI and serves it,
plus the `/api/*` control plane, from a single Flask process behind gunicorn (see the
[Dockerfile](../Dockerfile)). It deploys to [Fly.io](https://fly.io) using the committed
[`fly.toml`](../fly.toml) at the repo root.

## Fly.io

Fly needs the least dashboard/UI configuration: everything lives in the committed
`fly.toml`, and the whole deploy is two CLI commands. It does require a card on file
(usage is small for a single always-on machine — a few dollars a month).

Fly does **not** inject a `PORT` environment variable automatically for a Docker-based
deploy — gunicorn binds `$PORT` (see the Dockerfile `CMD`), so `fly.toml` sets `PORT`
explicitly under `[env]` and keeps it equal to `internal_port` (`8080` in both places).
A mismatch here means Fly routes to a port nothing is listening on and the app is
unreachable.

```sh
fly launch   # first time: detects the Dockerfile, creates the app, links fly.toml
fly deploy   # every deploy after that
```

`fly launch` will offer to overwrite the committed `fly.toml` with a generated one —
decline that and keep the committed version, which already has the settings below.

Key settings in [`fly.toml`](../fly.toml):

- **`[env] PORT` / `internal_port`** — kept in sync at `8080` (see above).
- **No `[build]` section** — flyctl auto-detects the Dockerfile at the repo root and
  builds it as-is.
- **`force_https = true`** — all traffic redirected to HTTPS.
- **`auto_stop_machines` / `auto_start_machines` / `min_machines_running = 1`** — the
  Fly Proxy can scale to zero when idle, but one Machine is always kept warm so a demo
  visitor never hits a scale-from-zero cold start.
- **`[[http_service.checks]]`** — an HTTP health check hits `GET /api/health` (a
  dependency-free liveness probe) every 15s, with a 10s grace period after start and a
  5s timeout, so Fly only routes traffic to a Machine that's actually up.
- **`[[restart]]`** — `on-failure` with up to 3 retries; this is Fly's default restart
  behavior for a Machine that exits non-zero, spelled out explicitly here.
- **`[[vm]]`** — `shared-cpu-1x` at 512MB (the `shared-cpu-1x` default is 256MB; bumped
  up for headroom with gunicorn's 2 workers).

## Resilience

A few small things compound into a deploy that stays up and degrades honestly:

- **Two independent restart layers.** Gunicorn's master process respawns a worker that
  dies (crash, OOM, hung request past `--timeout`); the hosting platform separately
  restarts the whole container if it becomes unresponsive. Neither depends on the other.
- **Worker recycling.** `--max-requests`/`--max-requests-jitter` retire each gunicorn
  worker after a few hundred requests (jittered so workers don't all recycle at once),
  bounding the blast radius of any slow memory leak without needing a manual restart.
- **A dependency-free health check.** `GET /api/health` does no I/O and touches no other
  actor, so it reports whether the process itself is alive — the signal Fly's health
  check above is configured to use.
- **Keep-warm.** `min_machines_running = 1` keeps one instance running at all times, so
  a demo visitor never hits a scale-from-zero cold start.
- **The scripted fallback is the last line of defense, not a crutch.** If a live run of
  the plain happy-path flow crashes unexpectedly, `/api/run` falls back to a committed
  golden trace (tagged `"_source": "fallback"`) rather than surfacing a raw error — the
  same trace is also served directly at `/api/fixtures/<id>`, and the frontend bundles it
  (`happyPath.json`) so the UI can render something even if the API is briefly
  unreachable. This only ever covers the one canonical happy-path config. A live failure
  on any other scenario (an active capability or attack) still returns an honest 500 —
  we never fake a successful run of a scenario the caller actually asked to see fail or
  succeed for real.
