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


## Prometheus operational alert rules

`infra/prometheus/alerts.yml` is mounted into Prometheus by the optional
observability Compose file. Rules evaluate API scrape failures, previously
connected Redis outages, persistent consumer lag, pending acknowledgements and
nonempty DLQ. Thresholds are **starter lab defaults**, not tuned SLOs, and the
lag gauges require enabling Redis metrics in the API. Inspect evaluated rules
at `http://127.0.0.1:9090/alerts`.

**Important:** Local Prometheus alert-rule evaluation does *not* deliver
notifications. A properly configured, authenticated Alertmanager or other
controlled notification sink is still required for production paging.
With streaming intentionally disabled, Redis metrics may report unreachable;
the Redis-outage rule only activates after the stream-group-exists gauge was
previously observed. Never expose Alertmanager or Grafana directly to
untrusted networks.
