# Roadmap — Shipped vs Planned

The distinction between demonstrated capability and future scope matters more than the volume of technologies in a diagram.

## Shipped in v0.1.0 (original release)

- Zeek JSON and Suricata EVE flow ingestion, canonical JSONL contract.
- Reproducible seeded telemetry simulator and model training.
- Time-ordered fit/calibration/holdout split, held-out metrics and provenance.
- Isolation Forest scoring, risk tiers and heuristic triage clues.
- SQLite/PostgreSQL-compatible storage and sequential idempotent ingestion.
- API-key-protected ingestion and alert updates, append-only alert status audit.
- Interactive responsive dashboard and offline-safe static assets.
- Local Compose deployment configuration, pytest and GitHub Actions CI.

## Shipped in v0.2 (Database integrity upgrade)

- Versioned Alembic migrations, with recognition of the earlier unversioned SQLite schema.
- Safe on-demand SQLite backup and tested restore to an isolated database.
- PostgreSQL 64-bit flow counter schema and dedicated query indexes.
- SQLite/PostgreSQL conflict-safe bounded upserts; event+alert atomicity; SQLite concurrency regression tests.
- No tested PostgreSQL integration environment yet; do not confuse SQL implementation with production verification.
- Retention and archival **policy documented**, but automated retention **not implemented**.

## Planned Phase 2 — Data infrastructure

- Asynchronous collector and queue with at-least-once delivery and retry/dead-letter handling.
- Multi-sensor correlation, entity keys and richer schema evolution beyond existing Alembic migrations.
- PostgreSQL integration/load testing for existing upserts; ClickHouse analytics aggregation.

## Planned Phase 3 — Reliable modeling

- Real authorized labeled benchmark; cross-site generalization and temporal group splits.
- Drift alerts, model registry, scheduled retraining, canary/shadow scoring, alert budget controls.
- Separate models per sensor/direction, feature attribution only where methodologically sound.

## Planned Phase 4 — Production guardrails

- OIDC/SSO, RBAC, rate limiting, TLS, secret manager and access logging.
- Observability stack, p95 latency/throughput SLOs, backups and disaster recovery.
- Contract tests against sensor log versions, security testing, containers signed and scanned.

**Not promised:** A live hosted environment, universal threat detection, validated 99%+ intrusion accuracy, or production Kubernetes deployment.
