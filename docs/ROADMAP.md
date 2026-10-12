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

## Implemented in v0.3–v0.4 (synthetic-first)

- UNSW prepared CSV offline evaluation **adapter** with IF/LOF/rule comparison, provenance hashing and leakage checks; requires user-supplied official CSVs for real benchmark result.
- OIDC RS256 JWT verification, role-scoped read/mutation endpoints and tests; external identity provider and complete browser PKCE login not verified.
- Redis Streams collector/worker, retry/dead-letter and idempotent database ingestion; CI includes Redis integration test, not real multi-site sensor streaming.
- Prometheus HTTP/ingestion metrics, additional source behavior/correlation heuristics, opt-in Grafana/Prometheus Compose configuration.
- Alembic revision `0003_soc_accountability`: analyst notes, assignments, actor-attributed triage history, detail and CSV export endpoints.
- Request-body and per-process mutation rate limits, defensive response headers.
- Trusted local model artifact registry with checksums, synthetic gates, shadow comparison, explicit promotion and rollback.
- Manual conservative unalerted-only JSONL archival with SHA256 manifest (not automated regulated retention).

**Still requiring external evidence:** official benchmark evaluation, live OIDC PKCE with IdP, TLS reverse proxy and staging deployment, real Zeek/Suricata continuous log test, production durability/failover/load benchmarking, signed artifacts and native browser E2E deployment. Until then these checklist requirements are **not 100% verified**.

## v0.5 data-contract readiness

- CIC-IDS2017 FlowMeter CSV standalone evaluation adapter; local synthetic fixtures verify data parsing, duplicate exclusion and three comparison algorithms, not real benchmark accuracy.
- Canonical data quality and SHA-256 lineage audit, optional model-checksum enforcement, offline asset and indicator enrichment.
- Multi-stage Docker recipe, TLS/OIDC proxy staging *example* and recurring dependency-audit workflow; production security and public deployment are **not verified**.
