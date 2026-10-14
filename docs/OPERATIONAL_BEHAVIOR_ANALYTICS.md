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


## Durable correlated behavior cases (revision 0004)

A **production worker**, not a notebook or mock endpoint, scans finalized
five-minute UTC windows and groups real stored `network_events` by source IP.
It detects co-occurring port diversity, destination fan-out and connection
bursts, and persists **one case per source/window**, with JSON signal labels
and observed ML-flagged-flow counts. Signals are *heuristic only*; even a
multi-signal finding does not prove an attack.

- **Migration:** `networkpulse db upgrade` to `0004_behavior_findings`. New
  `behavior_findings` and `behavior_finding_audit` tables preserve the
  existing flow alerts and historical records. Back up PostgreSQL with
  `pg_dump`, or SQLite with `networkpulse db backup`, before upgrading.
  The application intentionally refuses an out-of-date database.
- **Live worker:** `networkpulse behavior-worker --interval 60 --lookback 30
  --lateness 2`; a dedicated `behavior-worker` service is included under the
  Compose `streaming` profile. It uses the same database as the API and
  Redis Streams consumer. Start the API and migrate first. The worker
  processes only *completed* five-minute windows with a two-minute watermark
  to tolerate short out-of-order arrival. It retries via its next cycle;
  failed cycles exit for Docker restart supervision.
- **Historical authorized backfill:** `networkpulse behavior-worker --once
  --until 2026-10-14T12:00:00+00:00 --lateness 0 --lookback 60`.
  Operator must select the relevant historical period; no invisible infinite
  history sweep. Historical runs do not bypass role controls on the API.
- **Review API:** Viewer or above can query
  `GET /api/v1/intelligence/findings` with status/source/pagination filters
  and `GET /api/v1/intelligence/findings/{id}/history`.
  Analyst or Admin can `PATCH /api/v1/intelligence/findings/{id}` with
  `{"status": "investigating", "assigned_to": "analyst-1",
    "note": "Confirmed authorized inventory activity"}`. Status is one of
  open/investigating/resolved/false_positive; `assigned_to: null` unassigns.
  Each change inserts an actor-attributed audit record in the same DB
  transaction. Browser cookie CSRF and bearer OIDC role checks are unchanged.
- **SOC UI:** The Behavior Findings table displays persisted cases and an
  analyst-review action separate from model-anomaly alerts. Text is displayed
  with `textContent`, not raw HTML.
- **Concurrency:** SHA-256 deterministic ID for (source IP, start UTC, 5m)
  and database-native `ON CONFLICT DO UPDATE`. Late additional flows only
  increase evidence; they never silently reopen resolved/false-positive
  findings or reset assignment. Every cycle revisits a bounded lookback,
  which handles short late arrivals, worker restarts and retry after failure.

### Accuracy, capacity and rollout limitations

- Default thresholds are 12 distinct destination ports, 8 distinct hosts or
  120 flows/minute *in one finalized five-minute window*. These are fixed,
  configurable **investigation policy**, not supervised attack classifier
  thresholds; tune them on independent authorized captures and log the policy.
- The worker processes source groups in fixed database pages and fails
  visibly when the candidate cap is reached. SQL scans can be costly on
  heavily loaded PostgreSQL servers. Validate p95 query latency, throughput,
  disk/storage growth, query plan and index coverage at actual production
  scale before marking the deployment fully ready.
- Late flows outside the configured lookback do not automatically update
  prior cases: use an explicit dated backfill. Existing findings are not
  deleted automatically on raw flow retention. Coordinate privacy/retention
  policies and operator-approved incident disposition.
- The authorized UNSW-NB15 CI replay uses original raw, distinct dated
  capture files, and exercises production ingestion, read protection,
  correlation idempotency, case review and audit. Synthetic test fixtures in
  ordinary pytest assert concurrency/edge cases only; **no synthetic model
  accuracy is advertised as real performance**.
- Real external IdP/TLS staging, network operator licensing, high-rate load
  testing on actual infrastructure and independent penetration assessment
  remain separate deployment gates.
