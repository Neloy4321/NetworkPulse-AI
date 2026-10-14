# NetworkPulse AI — Verified Disaster Recovery Drill

## What this actually proves

This is an **executable operational recovery tool**, using real PostgreSQL
`pg_dump -Fc` / `pg_restore --single-transaction` or SQLite's consistent
backup API. It verifies a backup checksum, restores that snapshot into an
**existing, empty, separately named scratch database**, and checks migration
revision, relational integrity and row counts for flow records, alerts, SOC
audits, per-window behavior findings, cross-window incidents and MLOps
observations. It does **not** ever restore into or overwrite a production DB.

CI executes the same code on the real PostgreSQL 16 service with related
SOC data and on SQLite with a seeded audited case; the restored records
retain bigint flow counters, analyst assignment and incident disposition.
Tests are evidence of functional recoverability of a representative CI
database, **not an independently tested customer backup or production RTO**.

## Operator workflow: native PostgreSQL

Before maintenance, restrict access to the backup location (dedicated
encrypted filesystem; owner-only access). Run the CLI in a trusted
operations context that can reach the PostgreSQL server and has matching
`pg_dump` client and `pg_restore` binaries. Never commit backups,
manifests containing environment details, or production data to Git.

```bash
# 1. Actual live source. Quote URL values to protect shell metacharacters.
export DATABASE_URL='postgresql+psycopg://BACKUP_USER:PASSWORD@DB_HOST:5432/networkpulse'
networkpulse db check

# 2. An explicit *new*, owner-only target in an encrypted secured directory.
networkpulse db snapshot --output /secure/backup/networkpulse-20261014.dump

# 3. Verify artifact integrity independently of restore.
networkpulse db verify-snapshot --output /secure/backup/networkpulse-20261014.dump
# Record the output backup_sha256 in the incident/maintenance approval.

# 4. Provision an EMPTY, disposable PostgreSQL database with a
# deliberately different *_drill* name and no application traffic.
# This provisioning action is intentionally NOT automated here.
export DRILL_URL='postgresql+psycopg://DRILL_USER:PASSWORD@DB_HOST:5432/networkpulse_drill_20261014'
networkpulse db recovery-drill \
  --output /secure/backup/networkpulse-20261014.dump \
  --restore-url "$DRILL_URL" \
  --expected-sha256 '<APPROVED_64_CHAR_SHA256>' \
  --confirm-isolated-target
```

All commands return nonzero on a checksum, schema, backup tool, restore,
foreign-key, consent or target-safety failure. `recovery-drill` is
**fail closed** if a PostgreSQL target already has application tables;
it never issues `DROP TABLE`, `TRUNCATE`, `DROP DATABASE`,
`--clean` or `--create`. A failed restore requires operator
inspection/cleanup and a **new empty scratch target** before retrying.

The PostgreSQL source and restore roles must have the necessary dump/read
and scratch DDL/restore privileges. Protect credentials via an approved
secrets provider/temporary environment injection; a password in a shell
history or environment variable still carries exposure risk. Client
processes are invoked without a shell; passwords are never added to their
argument list or printed on errors.

**Docker:** the application image includes PostgreSQL client utilities
and the same `networkpulse` recovery commands. To write externally,
bind-mount a separate, owner-protected backup directory at an operator-
chosen path and override the default app command for a one-shot
maintenance invocation. Production replicas and all writers should be
quiesced per the operator's restore plan before any real recovery.
No automatic schedule or retention of backups is configured by this PR.

## SQLite drill

```bash
export DATABASE_URL='sqlite:////srv/networkpulse/data/networkpulse.db'
networkpulse db snapshot --output /secure/backup/networkpulse.sqlite
networkpulse db verify-snapshot --output /secure/backup/networkpulse.sqlite
networkpulse db recovery-drill \
  --output /secure/backup/networkpulse.sqlite \
  --restore-url 'sqlite:////tmp/networkpulse_drill_20261014.db' \
  --expected-sha256 '<APPROVED_64_CHAR_SHA256>' \
  --confirm-isolated-target
```

SQLite drill requires a target file that **does not exist**. On failure,
any newly created scratch file is removed; the source and backup file
remain untouched.

## Scope and external production sign-off

The snapshot manifest records engine, schema revision, checksum, byte
count and declared time. The manifest itself is **not signed**, and the
application does **not encrypt** backups. A matching SHA proves consistency
with an approved digest, not that the backup came from a trusted source.
Snapshots contain real source/destination addresses, identities and other
potentially sensitive operational data. Encrypt, restrict, retain and
destroy them according to applicable policy.

The restored SQL database is only **one** component of recovery:
- A trusted model artifact + pinned SHA-256, release/registry files,
  application configuration and TLS/OIDC secrets are stored separately.
- Redis append-only files, outstanding consumer group offsets, collector
  checkpoint and external audit/security systems require their own
  tested recovery runbook.
- A single `pg_dump` is a consistent PostgreSQL database snapshot but
  **not point-in-time recovery**; WAL archiving, incremental backups,
  multi-node HA and scheduled offsite retention require infrastructure.
- Restored counts are proof of **internal consistency**, not equivalence
  to rapidly changing live source data. For exact source-to-restore counts,
  establish a controlled source write/ingest barrier and record the
  maintenance change window. In particular, transactions committed after
  the snapshot are not in that backup.
- Set and test organizational **RPO/RTO, failover, key rotation, monitoring
  and authorized security review** on the actual target deployment.
  No live site has been touched by this CI integration.

Keep manual approvals and incident tickets outside this repository.
Do not publish raw dumps as test fixtures or a GitHub Actions artifact.
