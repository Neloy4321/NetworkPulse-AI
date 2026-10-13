# Continuous flow ingestion: Redis Streams (opt-in)

**Scope:** Redis-backed at-least-once transport in a single worker group; this is not an end-to-end network packet sniffer, Kafka platform or independently load-certified pipeline.

## Architecture

```
Zeek JSON conn.log / Suricata EVE JSONL
    → collector file tail + fsynced offset
    → Redis Streams XADD (bounded backlog)
    → XREADGROUP / XAUTOCLAIM (worker)
    → Pydantic flow validation
    → Isolation Forest scoring
    → conflict-safe DB event+alert transaction
    → XACK + XDEL
Failure beyond max attempts → dead-letter stream
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
- **Backpressure:** when backlog is full, XADD is blocked with an error and checkpoint does not advance. The collector should be restarted after reducing backlog.
- **Worker failure:** unacknowledged pending entries are eligible for XAUTOCLAIM after 30 seconds of inactivity. The max retry count is configurable in Python; failed deliveries beyond it go to a dead-letter stream.
- **Database integrity:** ACK only after transaction commit; alert and flow are transactional.
- **DLQ:** contains log metadata and must have restricted access and retention settings.
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
