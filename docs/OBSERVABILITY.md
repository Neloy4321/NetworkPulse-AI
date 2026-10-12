# Observability & Operations

Current runtime exports Prometheus-compatible HTTP counters and histogram buckets:

- `networkpulse_http_requests_total{route,method,status}`
- `networkpulse_http_request_seconds_bucket{route,method,le}`
- `networkpulse_flow_ingest_total{result}`
- `networkpulse_model_scoring_seconds_bucket{le}` (currently measures ingestion+scoring, not isolated inference)
- `networkpulse_alert_updates_total{status}`

`/metrics` is limited to Admin role under configured OIDC auth. In local mode it is accessible to anyone with local server access. Keep it on localhost or behind internal proxy. Route labels are API templates (not source IPs or arbitrary URLs) to bound cardinality.

Structured JSON access event entries include request ID, route, method, status and latency. IP addresses, Authorization headers and query parameters are excluded. Add a deployment-wide log shipper and retention policy before production.

**Not yet validated:** Grafana dashboards, Redis queue lag SLO alerts, app/worker cross-service tracing, delivery failures, distributed request rate limits and p50/p95/p99 under sustained load. HTTP Histogram samples can be aggregated into quantile estimates in Prometheus if deployed. No p95 SLA is claimed without a load test.
