# Operational source behavior analytics

This is an **active API + SOC dashboard runtime capability**, not a
notebook-only experiment. The endpoint reads the production `network_events`
SQL table populated by authenticated HTTP ingestion and the Redis Streams
worker. Event-key uniqueness already prevents duplicate HTTP/queue replays
from inflating behavioral flow counts.

## API contract

`GET /api/v1/intelligence/behavior?window_minutes=5&lookback_minutes=60&limit=30`

- Viewer/Analyst/Admin authentication through the existing OIDC mechanisms.
- One-minute or five-minute **UTC-aligned** flow windows, latest 60 minutes by
  default. `until` accepts timezone-aware ISO 8601 timestamps for archived
  investigations; optional `src_ip` is IPv4/IPv6 validated.
- Queries all committed flows in the selected time period in **SQL**, not
  a silently truncated sample. Lookback 1–1440 minutes, page size 1–100,
  offset capped at 10000. Pages limit output *groups*, not input flows.
- Exact per-source/window counts: flow rows, distinct destination ports,
  distinct destination hosts, anomalous flow flags from the deployed model,
  byte/packet totals, no-response flow count, flagged fraction and nominal
  flows/minute. `partial_window` identifies cut-off boundary buckets.
- Heuristic-only cues, configurable per request: `port_sweep_like`,
  `destination_fanout_like`, `connection_burst_like`. Defaults:
  12 ports, 8 hosts and 120 flows per minute equivalent. A cue is **not**
  evidence of a confirmed port scan, intrusion or malicious actor.
- No new schema tables or migration: historical stored flows are available.

## Real-data and SQL validation

CI's native real-data workflow downloads the user's authorized original
UNSW-NB15 raw archive with exact length and SHA-256 checks, fits the actual
Detector on earlier original `UNSW-NB15_1.csv`, then replays flows from
later held-out `UNSW-NB15_4.csv` via signed RS256 authenticated HTTP API.
It calls **the same operational behavior endpoint** and verifies exact
replayed flow totals and RBAC. Only aggregate CI evidence is archived.

Regression tests cover UTC bucket boundaries, distinct destinations,
deduplication, historical source filtering, partial windows, pagination and
invalid API parameters. The existing dedicated PostgreSQL CI test now also
runs the behavior SQL on PostgreSQL rather than SQLite alone.

## Deployment and capacity notes

- Existing `idx_flow_timestamp_src` and `idx_flow_src_timestamp`
  indexes support time/source predicates. Grouping may still become expensive
  as traffic increases; a response-group limit **does not cap rows scanned**.
  Check `EXPLAIN ANALYZE`, index choice and p95 query latency on real
  production volume. Add persisted rollups/partitioning when measured SLOs
  require them. Avoid running unbounded historical exports from the UI.
- Polling dashboard fetches behavior no more often than every 30 seconds;
  refresh error leaves core SOC overview usable.
- Behavior patterns are investigation hints only; this phase does *not*
  create new durable behavior-only incident records or automatically block IPs.
  That requires a separate, idempotent alert lifecycle.
- No claim of real external IdP, validated public HTTPS/Caddy staging,
  cross-site sensor coverage, independently measured operational detection
  accuracy, multi-worker failover testing or independent security assessment.
