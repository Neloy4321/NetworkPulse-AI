# Stage B — Real Disposable PostgreSQL and Redis Restart Evidence

**Scope:** Actual SIGKILL and restart of **owned, disposable GitHub CI containers**, with canonical synthetic events only. This is **not** production, multi-node HA, approved external staging, an ML benchmark, or an RPO/RTO certification. ML P0 remains NO-GO.

## Security boundaries

- Uses the previously implemented non-ML `SyntheticIntegrityHarness`, separate `networkpulse_staging_infra` DB and `networkpulse_staging` role. No detector training/inference, API ingestion, external captures, or actual sensor events.
- Runs only on GitHub Actions CI, behind exact confirmation flags and a per-run `npstageb-<numeric run ID>` Compose project. Remote Docker contexts and non-local Docker socket are prohibited.
- Before any SIGKILL, validates the container ID, exact project and service labels, expected Postgres 16/Redis 7 images, and exactly one published **127.0.0.1-only** CI port.
- Generates disposable per-run database/Redis secrets, excludes them from logs/evidence, refuses to overwrite existing evidence, and removes only this run's Compose volumes at workflow completion.
- Tests fail closed if a genuine stopped process cannot be observed. Failures cannot be relabeled PASS.

## Genuine two-service restart sequence

1. Commit 10 canonical synthetic events as a durable SQL baseline and enqueue 50 further events.
2. SIGKILL the owned PostgreSQL service, observe the stopped state and closed local port, attempt a real batch SQL write **while the database is down**, require 25 pending and all 50 unacknowledged messages in Redis. Restart the same container and reconnect; drain all 50 and reconcile the entire 60-event set.
3. Enqueue 50 more events, claim 13 into a consumer-group pending list, demand a positive `WAITAOF` acknowledgment before the crash, SIGKILL the owned Redis service, observe the stop and restart the same container with its persistent CI volume.
4. Verify all 13 pending events and 50 stream entries survived disk recovery; recover pending deliveries and drain the queue.
5. Verify all **110 accepted events** persist exactly once with canonical ID+SHA-256 digest reconciliation, zero queue depth, zero pending messages. Record measured restart-to-readiness durations for PostgreSQL and Redis.

The GitHub workflow uploads a metadata-only JSON artifact, including success/failure class, event accounting, and the explicit field `operational_acceptance: NOT_CLAIMED`. Uncontrolled CI runner timings must not be advertised as real-site latency or resilience SLOs.

## How to execute

The GitHub Actions workflow `Stage B disposable non-ML PostgreSQL and Redis real restart drill` runs automatically on PRs/main changes to its associated files, or can be manually dispatched. It reuses the existing Stage A Compose dependencies with the CI-only override and no public service.

Still pending: actual HTTPS staging domain and valid TLS chain, genuine external OIDC/RBAC, reliable independently measured throughput, encrypted/offsite restore drill and measured RPO/RTO, external alert delivery, rollback and 24–72h soak, and independent operator acceptance.
