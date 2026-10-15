# Isolated staging: sustained load, recovery and SLO evidence

This is **operator-executed acceptance software**, not a demo, an automatic
production fault injector, or a replacement for an independent external
failover exercise. It replays **unaltered and operator-authorized** Zeek,
Suricata or canonical flow metadata through the real Redis Streams transport,
the **signed approved native Detector** and an Alembic-migrated PostgreSQL
database. It measures Redis enqueue-to-ACK time; **not** packet-capture-to-alert
time. It runs a paced producer concurrently with an actual scoring and SQL
transaction consumer over the requested period.

## Non-negotiable isolation controls

1. Provision a disposable, isolated PostgreSQL database ending in `_staging`
   (or `_ci` for the CI service). Its exact name must match
   `--expected-database`, verified by PostgreSQL `current_database()`.
   It must have the current Alembic migrations, and it must not contain the
   run's flow IDs. The runner never updates or deletes existing SQL rows.
2. Use a dedicated, access-controlled Redis logical database **1..15**,
   separate from production's database 0. No production queue keys are used.
   The runner creates a unique `networkpulse:staging:<run-id>` stream/group.
   Never point it to a production Redis deployment, even with a nonzero DB.
3. Load an independently signed, **non-synthetic**, registry-active model and
   supply `NETWORKPULSE_MODEL_REGISTRY_ROOT`, `MODEL_PATH` and its exact
   `MODEL_SHA256`. The CLI validates the signed active release before
   unpickling its artifact. No unsigned model bypass is offered by the CLI.
4. Obtain written permission for the real source log and record its SHA-256.
   The runner validates source bytes before **and after** parsing, refuses
   simulation source records, duplicate canonical IDs and inadequate sample
   count. No source payload/IP, DB URL, Redis password, API key or signing
   secret is copied into evidence.
5. Require `--confirm-isolated-staging` explicitly. The CLI will refuse
   production database names, Redis database 0, unsigned model artifacts,
   unapproved source bytes, out-of-bounds load and existing output reports.

## Example operator invocation

Configure approved staging environment variables securely; do not put
passwords in command history or CI artifacts:

```bash
export DATABASE_URL='postgresql+psycopg://.../networkpulse_staging'
export REDIS_URL='rediss://.../1'
export NETWORKPULSE_MODEL_REGISTRY_ROOT='/secure/staging/registry'
export MODEL_PATH='/secure/staging/approved-model.joblib'
export MODEL_SHA256='<64-hex-approved-artifact-hash>'
export NETWORKPULSE_API_KEY='<secure-staging-key>'
sha256sum /secure/authorized/zeek-conn.jsonl

networkpulse staging-load \
  --source /secure/authorized/zeek-conn.jsonl \
  --format zeek \
  --source-sha256 '<64-lowercase-source-hash>' \
  --expected-database networkpulse_staging \
  --confirm-isolated-staging \
  --rate 20 \
  --duration-seconds 600 \
  --max-events 12000 \
  --drain-timeout-seconds 180 \
  --max-p99-seconds 10 \
  --min-throughput 15 \
  --report /secure/evidence/load-20261015-a.json
```

This sample defines a **target**, not an observed/certified capability.
Default sample rate is 20 flows/s for 60 seconds; configuration is bounded
to 1..500 flows/s, 10..3600 seconds and at most 50,000 unique events per
run. For longer or higher-volume site assessment, run independently
authorized separate campaigns with distinct pinned source windows and
immutable evidence files. Use a new isolated staging DB or nonoverlapping
real canonical flow IDs for each run. The tool never generates altered fake
IDs from real records to make counts look larger.

Exit code **0** means this local staging run met the specified acceptance
thresholds and exact Redis+SQL reconciliation; **2** means the run failed
or did not meet the operator threshold. It does **not** mean certified
production readiness. The JSON evidence includes model/corpus SHA-256,
unique run ID and stream key, actual duration/rate, published/ACKed/inserted
counts, observed queue-to-ACK p50/p95/p99, batch-cycle p50/p95/p99, peak
sampled stream depth and threshold verdict. Reports are mode 0600, fsynced
and created without overwriting an existing evidence path.

## What the controlled failure proves (and does NOT prove)

The consumer injects **exactly one pre-commit handler exception**; the
original Redis delivery must remain pending. It switches to a second
consumer identity and uses XAUTOCLAIM to recover that delivery while
the producer continues. All required flows must end in the database once,
with zero queue/pending/DLQ and exact new-row/ACK reconciliation. Unexpected
handler failures or backlog/drain deadline violations fail the run and
leave its Redis stream and PostgreSQL rows intact for investigation.

This is **not** Redis node failover, PostgreSQL node failover, forced
container SIGKILL or packet-to-alert timing. Perform those separately on a
dedicated staging deployment, recording Docker/container events,
Prometheus worker p95/p99, host CPU/memory, Redis AOF persistence,
PostgreSQL replication/WAL, controlled failure timestamps, return to
readiness, and independent data reconciliation. Operator paging,
alert delivery, RPO/RTO and false-positive requirements must be separately
signed off before claiming field SLOs. Never run failover experiments
against production without a preapproved maintenance and rollback plan.

## Failure and evidence retention

The run intentionally **does not delete Redis streams or SQL rows** on
success *or failure*. On failure, read the restricted JSON evidence,
inspect its unique stream name, reconcile pending entries against the
approved source and exported alert rows, then preserve appropriate
forensic artifacts. Do not blindly delete a queue, reset consumer offsets
or rerun an identical corpus into the same DB and treat that as fresh proof.

GitHub CI uses Redis 7 and PostgreSQL 16 for a 10-second correctness
integration with a clearly identified **synthetic fixture**. That test
checks the harness implementation only; the production CLI refuses a
synthetic/unapproved release or source. CI cannot substitute for a site
load campaign or independent production certification.
