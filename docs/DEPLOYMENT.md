# Deployment

The app is one container: a multi-stage build that compiles the React UI and serves it,
plus the `/api/*` control plane, from a single Flask process behind gunicorn (see the
[Dockerfile](../Dockerfile)). Nothing below is host-specific to the code — the same image
runs anywhere that can run a container and set `PORT`.

## Fly.io (recommended — least manual setup)

Fly needs the least dashboard/UI configuration: everything below lives in a committed
`fly.toml`, and the whole deploy is two CLI commands. It does require a card on file
(usage is small for a single always-on machine — a few dollars a month).

Gunicorn binds `$PORT` (see the Dockerfile CMD); Fly sets `PORT` to `internal_port` from
`fly.toml`, so keep the two in sync (`8080` below).

Commit a `fly.toml` like this at the repo root:

```toml
app = "oauth-threat-visualizer"
primary_region = "iad"

[build]

[env]
  PORT = "8080"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = "stop"
  auto_start_machines = true
  min_machines_running = 1   # keep one warm — avoids a cold-start blank screen

  [[http_service.checks]]
    grace_period = "10s"
    interval = "15s"
    timeout = "5s"
    method = "GET"
    path = "/api/health"

[[restart]]
  policy = "on-failure"
  retries = 3
```

Then:

```sh
fly launch   # first time: detects the Dockerfile, creates the app, writes fly.toml
fly deploy   # every deploy after that
```

## Cloud Run (free-tier alternative)

Cloud Run's free tier comfortably covers a low-traffic demo, at the cost of a one-time
setup in the GCP console (create a project, attach billing — required even to stay on the
free tier, but nothing is charged at this scale).

```sh
gcloud run deploy oauth-threat-visualizer \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 512Mi \
  --cpu 1 \
  --min-instances 1 \
  --max-instances 3 \
  --concurrency 40 \
  --timeout 60
```

Cloud Run manages container restarts itself and probes `/api/health` as a liveness and
startup check. `--min-instances 1` keeps one instance warm for the same reason as Fly's
`min_machines_running` — no cold-start delay on the first request after idle.

## Resilience

A few small things compound into a deploy that stays up and degrades honestly:

- **Two independent restart layers.** Gunicorn's master process respawns a worker that
  dies (crash, OOM, hung request past `--timeout`); the hosting platform separately
  restarts the whole container if it becomes unresponsive. Neither depends on the other.
- **Worker recycling.** `--max-requests`/`--max-requests-jitter` retire each gunicorn
  worker after a few hundred requests (jittered so workers don't all recycle at once),
  bounding the blast radius of any slow memory leak without needing a manual restart.
- **A dependency-free health check.** `GET /api/health` does no I/O and touches no other
  actor, so it reports whether the process itself is alive — the signal both Fly's and
  Cloud Run's probes above are configured to use.
- **Keep-warm.** Both configs above keep one instance running at all times, so a demo
  visitor never hits a scale-from-zero cold start.
- **The scripted fallback is the last line of defense, not a crutch.** If a live run of
  the plain happy-path flow crashes unexpectedly, `/api/run` falls back to a committed
  golden trace (tagged `"_source": "fallback"`) rather than surfacing a raw error — the
  same trace is also served directly at `/api/fixtures/<id>`, and the frontend bundles it
  (`happyPath.json`) so the UI can render something even if the API is briefly
  unreachable. This only ever covers the one canonical happy-path config. A live failure
  on any other scenario (an active capability or attack) still returns an honest 500 —
  we never fake a successful run of a scenario the caller actually asked to see fail or
  succeed for real.
