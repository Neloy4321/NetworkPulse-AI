# Actual Redis/PostgreSQL single-node crash and restart drill

This is **a real disposable Docker SIGKILL/restart test**, not a mocked
handler exception and not multi-node high-availability cluster failover.

The automatically run workflow
[`isolated-service-crash-drill.yml`](../.github/workflows/isolated-service-crash-drill.yml)
uses a GitHub-hosted, isolated Linux runner. It creates fresh, uniquely owned
PostgreSQL 16 and Redis 7 containers that only bind to `127.0.0.1`.
It migrates the real database schema and exercises the actual
Redis Stream consumer group, native ML scorer and transactional PostgreSQL
writer on 120 **synthetic CI fixture** flows.

The acceptance sequence verifies a committed/ACKed batch, then kills
the PostgreSQL container via actual Docker `SIGKILL` while the next
25 Redis messages are ready. The handler must leave that entire batch pending.
It restarts the exact same PostgreSQL container (its WAL is retained), then
a new consumer reclaims pending deliveries and drains the rest. Next, it
enqueues more flows, creates 20 unacknowledged Redis deliveries, SIGKILLs
Redis, restarts the same Redis container with AOF
`appendonly yes --appendfsync always`, and proves the previous
stream length and pending group entries survived the crash. It then
requires full drain, zero DLQ, zero pending and exactly matching
canonical event IDs in PostgreSQL.

A JSON artifact records the actual restart-to-readiness durations,
Redis queue-to-ACK p50/p95/p99, published count, successful ACK count,
distinct persisted SQL IDs, missing rows and remaining queue state. These
are **observations from the ephemeral runner**, not production benchmarks.

## Mandatory safety controls

- Requires **both** `--confirm-disposable-lab` and
  `NETWORKPULSE_ALLOW_ISOLATED_DOCKER_DRILL=I_ACCEPT_EPHEMERAL_CONTAINERS`.
- Rejects `DOCKER_HOST`, `DOCKER_CONTEXT`, non-default contexts and
  Docker endpoints without a local Unix socket.
- **Never accepts existing container identifiers, production DB URLs,
  production Redis URLs, source model paths or user-provided endpoints.**
  It creates new cryptographically random container names.
- Verifies the exact Docker ID, name, source image and two per-run ownership
  labels before every kill, restart or container removal.
- Containers publish only random, loopback-bound ports. Test credentials
  exist only in the ephemeral lab and are not stored in exported evidence.
- Removes only its verified owned containers. A failed cleanup fails the
  overall acceptance, requiring manual security-operator review.
- Writes metadata-only mode-0600 fsynced evidence without overwriting an
  existing report. Failure evidence includes only sanitized error categories.

To execute on a **reviewed, disposable local Linux Docker lab**, with
appropriate operator authorization:

```bash
export NETWORKPULSE_ALLOW_ISOLATED_DOCKER_DRILL=I_ACCEPT_EPHEMERAL_CONTAINERS
python -m networkpulse.container_failover \
  --confirm-disposable-lab \
  --report /secure/evidence/new-single-node-restart-drill.json
```

Do **not** interpret this as site-wide RPO/RTO, HA/failover certification,
real-data false-positive evaluation, sustained site p99, disaster recovery,
Redis replica promotion, PostgreSQL primary promotion or packet-to-alert
latency. The controlled lab uses Redis AOF fsync on every write; another
deployment policy may lose more writes. For these production claims the
operator must separately test the approved staging topology, capture
data, WAL/PITR backup restoration, orchestration, network partition,
CPU/memory, traffic backpressure, alert delivery and long-duration data
reconciliation. Do not disable network and ownership interlocks to run
the drill against production.
