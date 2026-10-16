# Stage B — Authenticated Encrypted PostgreSQL Snapshot and Scratch Restore

**Scope:** Disposable GitHub-hosted non-ML CI drill against synthetic data. The existing product backup routine in `networkpulse/recovery.py` is **unchanged and still writes unencrypted native dumps**. This new Stage B tool is **not** a production backup implementation, external-site restore, encrypted offsite retention plan, or certified RPO/RTO.

## What is genuinely exercised

1. Start separate ephemeral PostgreSQL 16 and Redis 7 in a unique Compose project, on loopback-only ports. Generate new DB/Redis credentials and a disposable 256-bit encryption key for this CI run. The runner must be GitHub-hosted CI with a default local Docker socket, explicit restart consent, separate DR consent, and correct owned-container labels, images and ports.
2. Insert exactly 180 unique canonical, non-ML synthetic events. Check source SQL count, SHA-256 row fingerprint, Redis stream depth/pending zero, and refuse if unrelated rows exist in the dedicated Stage B table.
3. Execute **real pg_dump custom format**, stream its bytes directly through **AES-256-GCM** with a random 96-bit nonce and authenticated associated metadata (source DB, table, run ID, row count, fingerprint), and write only ciphertext plus a metadata manifest to a 0700 CI directory. No plaintext database dump is written during backup. Encrypted files are created O_EXCL, NOFOLLOW, mode 0600.
4. Before restore, prove that wrong-key decryption and tampered encrypted-file checks fail closed. During restore, compare ciphertext checksum and verify the **entire AES-GCM tag** before any scratch DB creation. An authenticated plaintext dump exists briefly in a mode-0600 CI scratch file during pg_restore and is removed afterward. CI cleanup removes all archives and volumes.
5. Create a **new uniquely named empty scratch database** in the disposable CI PostgreSQL cluster (never overwrite an existing database). Execute real `pg_restore --single-transaction --exit-on-error --no-owner --no-acl`, re-query all restored receipts and compare exact row count, canonical sequence and SHA-256 fingerprint. Drop only this scratch DB.
6. Emit a **metadata-only** PASS/FAIL JSON report including encryption algorithm, wrong-key/tamper refusal, restored row count, encrypted-file SHA256, local backup and restore durations. CI uploads **only the report**. Neither ephemeral AES key nor dump bytes are uploaded to GitHub.

## Fail-closed limitations and operator cautions

- The key is ephemeral and purposely discarded; **the ciphertext is not retained**, and this is not an offsite backup usable for a future incident. Actual offsite persistence, secure KMS-managed key rotation, continuous restore jobs, backup schedule/retention, audit access controls and independent operations signoff remain outstanding.
- A temporary authenticated plaintext file exists during restore; secure deletion of physical storage remnants is not guaranteed. Real operators must use encrypted volumes or appropriately isolated ephemeral storage, and review the threat model before reusing this code outside disposable CI.
- CI measurements use an ephemeral single-node synthetic workload. Local backup/restore timings cannot be advertised as production RTO, RPO or SLA. No external incident-failure clock is started; RPO/RTO certification is explicitly NOT_CLAIMED.
- Even if all tests pass, external TLS/DNS, genuine OIDC/RBAC, independently controlled staging, alerts, soak, offsite DR, human review and ML P0 approval remain blocked.
- No real network sensors, external ML datasets, production database credentials, model files or attacker labels are used.

## Executing

Run the automated **Stage B encrypted PostgreSQL scratch recovery CI** GitHub Actions workflow on PR / main. The workflow generates all secrets, starts dedicated CI containers, runs safety unit tests and a real PostgreSQL backup/restore drill. Do **not** run its test-only Docker operations against a personal VPS, a shared GitHub self-hosted runner, or production-like persistent containers.

To audit a run, verify the workflow conclusion and uploaded metadata artifact alongside its exact Git commit SHA. One passing test does not complete the overall 12-category audit or confer 8–8.5/10 Non-ML operational readiness.
