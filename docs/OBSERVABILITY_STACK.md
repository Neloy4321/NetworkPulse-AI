# Opt-in Prometheus + Grafana for localhost

Run from repository root after setting a strong `NETWORKPULSE_API_KEY`, `POSTGRES_PASSWORD` and `GRAFANA_ADMIN_PASSWORD` in an **untracked** `.env`:

```bash
docker compose -f compose.yaml -f compose.observability.yaml up --build
```

Services bind to loopback: NetworkPulse `http://127.0.0.1:8000`, Prometheus `http://127.0.0.1:9090`, Grafana `http://127.0.0.1:3000`. Grafana dashboard is provisioned from `infra/grafana/dashboards/networkpulse.json`.

Telemetry: HTTP rate, p95 latency, errors, inserted flows, model-scoring latency and alert updates. Grafana metrics and panels are configured but **a live Docker Compose build and visualization were not verified in the authoring environment**. This is **single-process API metrics**; multi-process deployments need separate metrics aggregation. Redis lag, backlogs, worker crash alarms, traces and paging are future operational checks. Never expose this unprotected demo stack publicly; put the metrics endpoint and Grafana behind production-grade auth/TLS/reverse proxy.


## Redis worker queue observability (streaming profile)

With the streaming profile enabled, API `/metrics` scrapes bounded
Redis queue-state gauges through `REDIS_METRICS_URL`. This makes worker
queue state visible from the existing Prometheus target without exposing
flow payloads or duplicating a Prometheus registry across processes.

- `networkpulse_stream_redis_reachable` (1 for reachable, 0 for disconnected)
- `networkpulse_stream_depth` (main stream entries)
- `networkpulse_stream_pending` (delivered, unacknowledged messages)
- `networkpulse_stream_lag` (undelivered group messages)
- `networkpulse_stream_dead_letter_depth` (messages requiring investigation)
- `networkpulse_stream_consumers` and `networkpulse_stream_group_exists`

A missing group or unknown Redis lag yields NaN rather than an invented zero.
The scrape is optional, has short Redis timeouts, and stays available even if
Redis is unreachable. These are queue-state snapshots, not a throughput SLA.
The existing HTTP ingestion counter does not include worker-originated flows.
Avoid making production claims without live sensor/load tests.
