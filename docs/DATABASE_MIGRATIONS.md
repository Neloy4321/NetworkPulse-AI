# Database Integrity & Migration Runbook

> **Version:** 0.2 database upgrade. The migration is deliberately explicit: `networkpulse db upgrade`.
> Local tests cover SQLite, including an in-place v0.1 upgrade and backup/restore. PostgreSQL migration scripts are implemented but **not independently integration-tested with a running PostgreSQL server** in this release.

## What changed

- Alembic revisions: `0001_legacy_baseline` → `0002_counter_integrity` → `0003_soc_accountability` → `0004_behavior_findings`.
- PostgreSQL `network_events.orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts` use `BIGINT`. SQLite's `INTEGER` already supports signed 64-bit values and is left intact.
- Indexes optimized for `(anomalous, timestamp)`, `(src_ip, timestamp)` and `(status, created_at)`; their effectiveness on real workload still needs query-plan benchmarking.
- Ingestion uses atomic PostgreSQL/SQLite `INSERT ... ON CONFLICT DO NOTHING ... RETURNING`, in bounded batches, with event and alert creation in **one transaction**.
- Foreign-key enforcement is explicitly enabled for SQLite runtime connections.
- Ingestion remains **at-least-once delivery friendly**, not an external exactly-once message-transport guarantee. Two workers may score the same flow, but only the database-accepted event is persisted, with one alert.

## Local install or upgrade (Windows PowerShell)

1. **Stop the running Uvicorn server** with `Ctrl+C` before upgrading source and database.
2. Activate your virtual environment and install updated dependencies:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   python -m pip install -e ".[dev]"
   ```

3. If your `data/networkpulse.db` already exists, take an explicit snapshot:

   ```powershell
   networkpulse db backup --output data/networkpulse-before-upgrade.db
   ```

4. Run the upgrade (it also automatically backs up a nonempty SQLite DB when a new revision is needed):

   ```powershell
   networkpulse db status
   networkpulse db upgrade
   networkpulse db status
   ```

5. Start the existing demo as usual:

   ```powershell
   networkpulse bootstrap
   uvicorn networkpulse.api:create_app --factory --host 127.0.0.1 --port 8000
   ```

**Important:** Running an older ZIP copy of the source will not gain new functionality just because GitHub was updated. Download/clone the revised repository into a **separate folder**, or update a true Git checkout. Keep your original `data/` folder backed up before switching.

## Existing legacy database migration

An unversioned database with the expected original three tables is recognized as the v0.1 baseline, stamped with `0001_legacy_baseline`, then advanced to `0002_counter_integrity` → `0003_soc_accountability` → `0004_behavior_findings`. Unknown or partial legacy schemas are rejected. This operation **preserves preexisting network events and alert records** in the SQLite migration regression test.

If you already have an Alembic-managed database, rerunning `networkpulse db upgrade` is idempotent. Do not delete `alembic_version` manually.

## PostgreSQL migration / Compose

For PostgreSQL, take a separate database backup first, for example using `pg_dump -Fc` with your own credentials and secure output destination. Test `pg_restore` in a **separate staging database** before upgrading production. The application requires the schema at the current revision before starting; the included **local-development** Compose command runs a migration before demo bootstrapping.

A schema migration should run as **one controlled job**, not concurrently on all production replicas. `BIGINT` alteration may take locks; allow a maintenance window. Check PostgreSQL role privileges, disk, recovery plan, and long-running transactions.

**Not yet validated:** PostgreSQL-backed integration tests, advisory-lock coordination during migrations, lock-time/throughput performance, WAL archival, point-in-time recovery, or production-safe rolling migrations.

## Recovery and rollback

- **SQLite:** Stop all application processes, keep a copy of the failed DB, and restore from your verified SQLite snapshot (not while the database is live). The test suite validates that a SQLite snapshot can be restored into a new database and its event/alert counts recovered.
- **PostgreSQL:** Restore from tested `pg_dump` or point-in-time recovery infrastructure. We intentionally do **not** implement automatic down-migration from `BIGINT` to `INTEGER` because narrowing can lose data.
- **Model artifacts:** `data/model.joblib` is a separate trusted artifact; upgrading the SQL schema does not retrain or rewrite the model.

## Retention and archiving — policy, not yet automation

Choose retention limits based on the network's compliance and operational requirements; do not automatically purge data in v0.2. A potential starting point for a nonregulated lab is 30 days of raw flow events and 90 days of alert/audit data, but these are **policy examples, not configured defaults**.

Production implementation needs export/checksum verification, retention of linked audit data, separate hot/cold storage, privacy controls, restore drills, and versioned migration to partitioned event tables. **Automatic retention and archival are planned, not yet implemented.**

## Commands

| Command | Operation |
| :--- | :--- |
| `networkpulse db status` | Show Alembic revision and readiness |
| `networkpulse db upgrade` | Upgrade local SQLite or configured PostgreSQL DB |
| `networkpulse db backup --output ./db-snapshot.sqlite` | SQLite backup (refuses overwrite) |

To use PostgreSQL, set `DATABASE_URL` for this process, along with the relevant database credentials. The DB subcommands do not need an API key.

## v0.4 addendum

Alembic revision `0003_soc_accountability` adds `alerts.assigned_to`, `alert_audit.actor`, and `alert_notes` with supporting indexes. Upgrades from the original v0.1 legacy schema or migrated v0.2 preserve existing event and alert IDs; new actor fields are null for historical operations. Tests exercise upgrades from both starting states. The same `networkpulse db upgrade` command applies, with an automatic SQLite pre-migration snapshot.

## v0.5+ operational MLOps evidence migration

Revision `0005_mlops_drift_runs` adds immutable, model-SHA and exact-input-fingerprint keyed drift monitoring history. Existing flow, alert, SOC and behavior case tables are unchanged. Apply `networkpulse db upgrade` with a verified backup before deploying either the API or `mlops-worker`. Models and original flow rows are not copied into this table; only aggregate PSI/alert-volume reports are stored.
