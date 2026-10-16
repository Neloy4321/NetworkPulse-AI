# Stage B — Isolated Non-ML Event Integrity and Bounded Load

**Status:** Code on feature branch; CI and external staging proof are separate gates.
**Scope:** Controlled synthetic event transit and durable database accounting. NOT an ML benchmark, IDS acceptance, or production deployment.

## Guardrails and design

- Reuses existing FlowStream and its Redis XADD/backpressure, consumer groups and database-commit-before-ACK guarantees. No Detector imports, model loading, inference, real flow ingestion or label handling.
- Requires dedicated staging PostgreSQL database networkpulse_staging_infra AND networkpulse_staging database identity. SQL checks actual current_database/current_user; unlike a name-only check, misconfigured credentials do not silently cross into the product DB.
- CLI requires explicit isolated mode, dedicated credentials and I_ACCEPT_ISOLATED_SYNTHETIC_STAGE_B consent; neither real OIDC tokens nor user payloads are used.
- Redis keys are uniquely prefixed networkpulse:stage-b:synthetic:<run-id>. Consumer group is stage-b-workers.
- Only np_stage_b_synthetic_receipts is created, in the isolated staging database. Primary key (run_id,event_id) makes effect idempotent; SHA-256 digest mismatch aborts the SQL transaction.
- Simulates only canonical synthetic IDs and ordinals, without external sources, IP addresses, network payloads or authentication details.
- Bounded queue capacity creates genuine XADD backpressure; rejected enqueues do not increase accepted counts. Queue ACK is after successful SQL transaction.
- Reconciliation checks every accepted ID and digest against every SQL receipt, plus Redis stream and pending depth both zero. Any mismatch fails closed.

## Ephemeral CI acceptance *of code*, not infrastructure production

The Stage B workflow starts dedicated PostgreSQL 16 and Redis 7 on CI-local loopback ports, with randomly generated credentials, never operator secrets. Tests cover mode refusal, bounding and canonical forms, real Redis/PG 250-event backpressure, simulated transient DB failure, Redis ACK link failure after SQL commit with exact-once DB effect during replay, poison/foreign-run validation, and a separate real 300-event bounded CLI observation.

The artifact reports accepted/persisted/ACK counts, queue pending and depth, backpressure events, observed event throughput, and p95/p99 end-to-end latency **in CI only**. Latency is measured from confirmed queue acceptance until successful ACK; timings represent an uncontrolled shared CI host, not a production performance SLA. No external-sensor or independent-operator reliability claims follow from green CI.

## Run only on authorized isolated staging

Configure dedicated PostgreSQL and Redis credentials securely; configure NETWORKPULSE_STAGING_MODE to non_ml_infrastructure_only, NETWORKPULSE_STAGING_DB_NAME to networkpulse_staging_infra, and NETWORKPULSE_STAGE_B_CONFIRM to I_ACCEPT_ISOLATED_SYNTHETIC_STAGE_B. Host and port may be set with NETWORKPULSE_STAGING_DB_HOST/PORT and NETWORKPULSE_STAGING_REDIS_HOST/PORT.

Run: python -m networkpulse.infra_event_harness --events 300 --max-backlog 100

Optionally add --cleanup to remove only this test run's synthetic receipts and Redis keys. Without cleanup, operator owns retention and deletion. Preserve commit SHA, environment inventory, service logs, resource use, report and review independently.

## Still blocked or outstanding

Verified external HTTPS/DNS/certificate chain, genuine IdP sessions and RBAC; independent load SLO, real host Redis/PostgreSQL process restart, durable snapshot encryption/offsite retention and restore RPO/RTO; alert notification and acknowledgment; rollback, secret rotation, 24–72h soak and human acceptance all remain separately pending. P0 ML acceptance stays NO-GO.
