# Opt-in Prometheus + Grafana for localhost

Run from repository root after setting a strong `NETWORKPULSE_API_KEY`, `POSTGRES_PASSWORD` and `GRAFANA_ADMIN_PASSWORD` in an **untracked** `.env`:

```bash
docker compose -f compose.yaml -f compose.observability.yaml up --build
```

Services bind to loopback: NetworkPulse `http://127.0.0.1:8000`, Prometheus `http://127.0.0.1:9090`, Grafana `http://127.0.0.1:3000`. Grafana dashboard is provisioned from `infra/grafana/dashboards/networkpulse.json`.

Telemetry: HTTP rate, p95 latency, errors, inserted flows, model-scoring latency and alert updates. Grafana metrics and panels are configured but **a live Docker Compose build and visualization were not verified in the authoring environment**. This is **single-process API metrics**; multi-process deployments need separate metrics aggregation. Redis lag, backlogs, worker crash alarms, traces and paging are future operational checks. Never expose this unprotected demo stack publicly; put the metrics endpoint and Grafana behind production-grade auth/TLS/reverse proxy.
