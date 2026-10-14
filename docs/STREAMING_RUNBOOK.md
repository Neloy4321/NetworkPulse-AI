# Continuous flow ingestion: Redis Streams (opt-in)

**Scope:** Redis-backed at-least-once transport in a single worker group; this is not an end-to-end network packet sniffer, Kafka platform or independently load-certified pipeline.

## Architecture

```
Zeek JSON conn.log / Suricata EVE JSONL
    → collector file tail + fsynced offset
    → Redis Streams atomic Lua XADD (strict cross-producer backlog cap)
    → XREADGROUP / XAUTOCLAIM (worker)
    → Pydantic validation (poison isolated)
    → batched native Detector scoring (up to 25 flows)
    → one conflict-safe DB event+alert transaction per batch
    → XACK + XDEL after durable commit
Permanent schema/JSON poison after bounded attempts → DLQ
Transient DB/model outage → pending retention, never DLQ
```

## Local setup

1. Install extra: `python -m pip install -e '.[streaming]'`
2. Run a Redis 7 instance on an **internal** interface with append-only persistence (`appendonly yes`, `maxmemory-policy noeviction`), access controls and TLS in production.
3. Set `REDIS_URL=redis://127.0.0.1:6379/0` for a local-only trusted lab.
4. Create/migrate DB and bootstrap a model: `networkpulse db upgrade && networkpulse bootstrap`.
5. Run worker: `networkpulse worker --consumer workstation-1`.
6. Run collector separately: `networkpulse collect --format zeek --path /path/to/conn.log --checkpoint data/zeek-offset.json`.

Docker Compose has an **optional** `streaming` profile for Redis and a worker:

```bash
docker compose --profile streaming up --build
```

Collector can run on a host with authorized access to Zeek/Suricata logs. Log file rotation detection is best effort, and only **one collector** should own a checkpoint. Source lines larger than 1 MB and malformed records stop the collector; correct or quarantine them rather than silently dropping metadata. The collector intentionally does not access raw packet payloads.

## Failure semantics and known limitations

- **At-least-once:** a crash after XADD but before checkpoint can publish a duplicate; database upsert keeps one flow and alert.
- **Atomic backpressure:** all collectors use one Redis Lua EVAL operation combining XLEN and XADD; independent processes cannot jointly exceed the configured stream-entry cap. Redis capacity errors fail closed; the collector checkpoint does not advance. Never use XADD MAXLEN truncation on uncommitted events.
- **Worker failure:** unacknowledged pending entries are eligible for XAUTOCLAIM after 30 seconds of inactivity. One read batch (up to 25 validated flows) is scored and committed in a single DB transaction. Redis XACK and XDEL follow a successful commit. If the process dies after DB commit but before ACK, PostgreSQL/SQLite uniqueness makes the retry idempotent. Validation/JSON-format failures alone have bounded poison retries and then enter a DLQ; database connection/model-processing exceptions **remain pending** no matter the delivery count and require operator alerting. This avoids silently discarding legitimate traffic during a long outage.
- **Database integrity:** ACK only after transaction commit; alert and flow are transactional.
- **DLQ:** contains original metadata/IPs (no PCAP). Restrict Redis ACLs, network exposure and retention. A reviewed item can be moved back to the live stream *atomically* only with an explicit entry ID and matching SHA-256. Invalid schema cannot be blindly replayed: repair/redact it via an authorized upstream process and emit a new separately audited record. Do not auto-drain poison messages.
- **No end-to-end SLA claimed:** persistent volumes, alerting, failover, network drop measurements, graceful fleet shutdown and worker throughput remain to be independently verified.


## Worker healthcheck (Docker Compose)

The API and worker share a built Docker image, but the API image's default
healthcheck uses HTTP `/health/ready` on port 8000. The background worker
does **not** run an HTTP server, so that inherited check incorrectly marks
an otherwise-running worker `unhealthy`.

The Compose `worker` service overrides the inherited check with a bounded
Redis `PING` using the worker's own `REDIS_URL`. This verifies Redis
connectivity and the container remains running, **not** that messages were
processed successfully. Idle workers may legitimately produce no logs.

Run in the project directory:

```powershell
docker compose --profile streaming up -d --no-deps --force-recreate worker
docker compose --profile streaming ps
```

To verify end-to-end processing, enqueue a new unique flow and inspect
database insertion and consumer acknowledgement separately; an `Up
(healthy)` status alone is insufficient.


## Operator investigation of dead letters

```bash
networkpulse stream-dlq inspect --limit 30
# Verify source, reason, approved flow record in the private Redis environment.
# The command prints metadata IDs and event SHA256, never raw flow contents.
networkpulse stream-dlq replay --id 1700000000000-0 \
  --approved-sha256 '<reviewed-event-SHA256>' --confirm
```

**Replay policy:** The operator must verify the original metadata using the
restricted Redis service and authorize the checksum, not blindly assume a
hash is an approval. Requeue is a single Lua script: it refuses a full live
queue and moves the exact DLQ entry after adding an XADD, rather than
deleting first. It will not accept a malformed FlowEvent. Replayed delivery
remains at-least-once. DLQ operations require operator-only Redis ACL access;
never expose a public web endpoint for this command.

## Verified performance and operational SLOs

- Quality CI uses Redis 7 and PostgreSQL 16; tests verify a 170-producer-attempt
  concurrent capacity bound of exactly 100, outage recovery, poison
  isolation, manual DLQ replay, and a 300-flow native Detector/DB batch
  integration run with logged observed flows/sec and per-batch timing.
- The real UNSW-NB15 CI job additionally replays 800 genuine later-capture
  flows through both OIDC-authenticated HTTP and Redis worker into the same
  private event table, verifying exact count, 0 Redis pending and 0 DLQ.
  The CI host throughput measurement is descriptive **only**, not a field SLO.
- Worker batches are bounded at 25 entries and source flow documents at the
  existing strict schema. Duplicate keys on retries are expected, not extra
  anomaly alerts. A model/DB exception must leave valid batch pending;
  page on rising age/backlog and inspect the database rather than manually
  deleting stream entries.
- Before any live deployment, measure p50/p95/p99 age of oldest pending
  Redis entry, packet-to-alert latency and bursts during a controlled
  target-network load, size Postgres connections and Redis storage for actual
  peaks, and rehearse Redis failover, dead-letter retention and DB restore.
  No numeric deployment throughput or incident MTTR is certified by CI.


## Processing integrity and production queue-age telemetry (October 2026)

Redis Lua scripting does **not** roll back commands executed before a script
raises. Batch ACK now preflights every pending ID (and rejects duplicates)
before any XACK/XDEL. Dead-letter transfer also confirms that its original
message is pending **before** XADD to the DLQ. A missing or already-ACKed
source cannot create an orphaned DLQ copy. These operations protect normal
Redis group state; they do not address privileged Redis tampering, storage
failures, or crash recovery without appropriately configured/persisted AOF.

The stream worker now executes a read-only `SELECT 1` against its own
configured database whenever an empty or poison-only Redis read would
otherwise refresh its success heartbeat. A lost PostgreSQL connection
causes the worker to exit rather than report fresh-but-false health.
Docker Compose includes `restart: unless-stopped` and a controlled
30-second stop grace period. Transient handler/model/database failures during
a *non-empty* batch continue to preserve legitimate pending messages for
retry; an unhealthy but running container still needs host alerting.

A new Prometheus gauge `networkpulse_stream_oldest_age_seconds` measures
**Redis queue residence time** for the oldest live entry (including pending
entries), from Redis-assigned stream ID and Redis server clock. It is zero
when the stream is empty and NaN/unknown when Redis cannot be observed.
This is not sensor-to-alert latency: collect and correlate actual sensor
ingest timestamps before defining end-to-end SLOs.

The observability rules warn when the oldest queued flow exceeds 120 seconds
for three minutes, and critically alert on a nonempty stream with no
consumer group. A Redis-unreachable alert now evaluates previously observed
group existence over the trailing hour to avoid treating an unknown metric
as a healthy empty queue. Configure an authenticated paging channel; local
Prometheus rules alone **do not send notifications**. The default 120-second
threshold is not a certified site SLO and must be replaced with measured
targets for each deployment.

Regression gates exercise the real Redis pending list, invalid ACK batches,
DLQ transfer refusal, and a 1,000-flow Redis/PostgreSQL scorer burst with
a fault injected before the first transaction, followed by worker recovery
and exact persisted-ID reconciliation. CI measurements are host-specific
functional evidence, not independent traffic throughput certification.
