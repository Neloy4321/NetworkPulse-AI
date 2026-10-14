"""Durable Redis Streams flow transport and batch PostgreSQL scoring.

Exactly-once *effects* come from database uniqueness, NOT Redis delivery.
Redis acknowledges only after the whole database transaction commits.
Permanent format/schema errors are isolated; transient DB/model failures stay
pending and are never silently dead-lettered by retry count.
"""
from __future__ import annotations

import json
import os
import socket
from collections.abc import Callable

STREAM = "networkpulse:flow:stream"
DLQ = "networkpulse:flow:dead_letter"
GROUP = "networkpulse-workers"

# Redis EVAL keeps length check and XADD in one atomic operation across all
# producer processes, including collectors on separate nodes. No MAXLEN
# trimming: entries are deleted ONLY after database commit or DLQ transfer.
_ENQUEUE_SCRIPT = """
if redis.call('XLEN', KEYS[1]) >= tonumber(ARGV[1]) then
  return false
end
return redis.call('XADD', KEYS[1], '*', 'event', ARGV[2])
"""

# XACK must succeed before XDEL. MULTI/EXEC does NOT roll back an
# XDEL following a command-level XACK error; Lua aborts at redis.call error.
_ACK_SCRIPT = """
-- Lua errors do not roll back previous Redis operations. Check every pending
-- entry before any XACK; reject nonexistent/duplicate IDs without partial ACK.
if #ARGV < 2 then return redis.error_reply('EMPTY_ACK_BATCH') end
local seen = {}
for i=2,#ARGV do
  if seen[ARGV[i]] then return redis.error_reply('DUPLICATE_ACK_ID') end
  seen[ARGV[i]] = true
  local pending = redis.call('XPENDING', KEYS[1], ARGV[1], ARGV[i], ARGV[i], 1)
  if #pending ~= 1 or pending[1][1] ~= ARGV[i] then
    return redis.error_reply('ACK_COUNT_MISMATCH')
  end
end
local acknowledged = redis.call('XACK', KEYS[1], ARGV[1], unpack(ARGV, 2))
if acknowledged ~= #ARGV - 1 then
  return redis.error_reply('ACK_COUNT_MISMATCH')
end
return redis.call('XDEL', KEYS[1], unpack(ARGV, 2))
"""

# XADD dead-letter event MUST succeed before acknowledging/deleting the
# original message. Redis Lua redis.call errors abort the subsequent actions.
_DLQ_SCRIPT = """
-- Refuse a missing group-pending source before adding DLQ records, avoiding
-- ghost copies if a later XACK would have returned zero.
local pending = redis.call('XPENDING', KEYS[1], ARGV[4], ARGV[1], ARGV[1], 1)
if #pending ~= 1 or pending[1][1] ~= ARGV[1] then
  return redis.error_reply('DLQ_SOURCE_NOT_PENDING')
end
local dlq_id = redis.call('XADD', KEYS[2], '*',
   'event', ARGV[2], 'source_id', ARGV[1], 'reason', ARGV[3],
   'origin_stream', KEYS[1])
local acknowledged = redis.call('XACK', KEYS[1], ARGV[4], ARGV[1])
if acknowledged ~= 1 then
  return redis.error_reply('ACK_COUNT_MISMATCH')
end
redis.call('XDEL', KEYS[1], ARGV[1])
return dlq_id
"""

# Move a selected DLQ entry back to the original live stream atomically.
# Operators must audit/checksum an item before replay (see replay_dead_letter).
_REQUEUE_SCRIPT = """
local rows = redis.call('XRANGE', KEYS[2], ARGV[1], ARGV[1])
if #rows == 0 then return false end
if redis.call('XLEN', KEYS[1]) >= tonumber(ARGV[2]) then
  return 'BACKPRESSURE'
end
local fields = rows[1][2]
local payload = false
for i=1,#fields,2 do
  if fields[i] == 'event' then payload = fields[i+1] end
end
if not payload then return 'MALFORMED' end
local new_id = redis.call('XADD', KEYS[1], '*', 'event', payload,
                         'dlq_source_id', ARGV[1])
redis.call('XDEL', KEYS[2], ARGV[1])
return new_id
"""


class BackpressureError(Exception):
    """The live stream is full; callers must not advance source checkpoints."""


class FlowStream:
    def __init__(self, redis_client, *, stream: str = STREAM, group: str = GROUP,
                 max_backlog: int = 50000, max_attempts: int = 5,
                 dead_letter: str | None = None):
        if max_backlog < 100 or max_attempts < 1:
            raise ValueError("invalid Redis Streams configuration")
        self.redis = redis_client
        self.stream = stream
        self.group = group
        self.dead_letter = dead_letter if dead_letter is not None else (
            DLQ if stream == STREAM else stream + ":dead_letter"
        )
        self.max_backlog = max_backlog
        self.max_attempts = max_attempts

    def initialize(self):
        try:
            self.redis.xgroup_create(self.stream, self.group, id="0-0", mkstream=True)
        except Exception as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def enqueue(self, event: dict) -> str:
        encoded = json.dumps(event, separators=(",", ":"), allow_nan=False)
        result = self.redis.eval(_ENQUEUE_SCRIPT, 1, self.stream,
                                 self.max_backlog, encoded)
        if not result:
            raise BackpressureError(
                "Redis flow backlog at capacity; collector offset was not advanced"
            )
        return str(result)

    def _messages(self, consumer: str, block_ms: int = 1000, count: int = 25):
        result = self.redis.xreadgroup(self.group, consumer, {self.stream: ">"},
                                       count=count, block=block_ms)
        return [entry for _stream, entries in result for entry in entries]

    def _recover(self, consumer: str, idle_ms: int = 30000, count: int = 25):
        _next_id, entries, *_ = self.redis.xautoclaim(
            self.stream, self.group, consumer, min_idle_time=idle_ms,
            start_id="0-0", count=count,
        )
        return entries

    def _entries(self, consumer: str, *, recover: bool = True,
                 block_ms: int = 1000, recover_idle_ms: int = 30000):
        entries = self._recover(consumer, idle_ms=recover_idle_ms) if recover else []
        return entries or self._messages(consumer, block_ms=block_ms)

    def _ack_many(self, ids: list[str]) -> None:
        if ids:
            self.redis.eval(_ACK_SCRIPT, 1, self.stream, self.group, *ids)

    def _ack(self, msg_id: str) -> None:
        self._ack_many([msg_id])

    def _dead_letter(self, msg_id: str, fields: dict, reason: str) -> None:
        # Original payload remains in Redis until DLQ XADD is successful.
        # This is Lua-atomic and aborts on command errors before ACK/XDEL.
        self.redis.eval(
            _DLQ_SCRIPT, 2, self.stream, self.dead_letter,
            msg_id, fields.get("event", ""), reason[:100], self.group,
        )

    def _deliveries(self, msg_id: str) -> int:
        info = self.redis.xpending_range(
            self.stream, self.group, msg_id, msg_id, 1,
        )
        return int(info[0].get("times_delivered", 1)) if info else 1

    def _permanent_failure(self, msg_id: str, fields: dict, exc: Exception,
                           outcome: dict) -> None:
        if self._deliveries(msg_id) >= self.max_attempts:
            self._dead_letter(msg_id, fields, type(exc).__name__)
            outcome["dead_lettered"] += 1
        else:
            outcome["retried"] += 1

    def consume_once(self, consumer: str, handler: Callable[[dict], None],
                     *, recover: bool = True, block_ms: int = 1000,
                     recover_idle_ms: int = 30000) -> dict:
        """Legacy single-record API. Runtime uses consume_batch_once below."""
        out = {"processed": 0, "retried": 0, "dead_lettered": 0}
        for msg_id, fields in self._entries(
            consumer, recover=recover, block_ms=block_ms,
            recover_idle_ms=recover_idle_ms,
        ):
            try:
                payload = json.loads(fields["event"])
                handler(payload)
            except (ValueError, KeyError, TypeError) as exc:
                self._permanent_failure(msg_id, fields, exc, out)
            except Exception:
                # Database timeout, outage, model failure: NEVER poison/DLQ.
                out["retried"] += 1
            else:
                self._ack(msg_id)
                out["processed"] += 1
        return out

    def consume_batch_once(
        self, consumer: str, handler: Callable[[list], None],
        validator: Callable[[dict], object], *,
        recover: bool = True, block_ms: int = 1000,
        recover_idle_ms: int = 30000,
        on_handler_failure: Callable[[], None] | None = None,
        on_committed: Callable[[list[str]], None] | None = None,
    ) -> dict:
        """Validate before scoring; one DB commit per valid Redis read batch.

        Any invalid record stays pending for bounded retries and then moves to
        DLQ. A failed DB batch is left pending in FULL, so no valid flow gets
        ACKed or DLQed during DB unavailability. A successful DB commit followed
        by Redis failure can replay; DB ON CONFLICT is the safety contract.
        """
        entries = self._entries(
            consumer, recover=recover, block_ms=block_ms,
            recover_idle_ms=recover_idle_ms,
        )
        out = {"processed": 0, "retried": 0, "dead_lettered": 0}
        good_ids = []
        good_payloads = []
        for msg_id, fields in entries:
            try:
                payload = json.loads(fields["event"])
                validated = validator(payload)
            except (ValueError, KeyError, TypeError) as exc:
                self._permanent_failure(msg_id, fields, exc, out)
            else:
                good_ids.append(msg_id)
                good_payloads.append(validated)
        if not good_ids:
            return out
        try:
            handler(good_payloads)
        except Exception:
            # A temporary PostgreSQL outage must not exhaust poison retries.
            # Tell the supervisor WITHOUT exposing the database error or flow
            # payload. The callback may fail closed if its budget has elapsed.
            if on_handler_failure is not None:
                on_handler_failure()
            out["retried"] += len(good_ids)
            return out
        self._ack_many(good_ids)
        # The database is committed and Redis has acknowledged/deleted each
        # message. Optional telemetry can never turn this into a failed batch.
        if on_committed is not None:
            try:
                on_committed(good_ids)
            except Exception:
                # Never expose payloads, Redis IDs or backend credentials.
                import logging
                logging.getLogger(__name__).warning(
                    "stream_post_commit_telemetry_unavailable"
                )
        out["processed"] += len(good_ids)
        return out

    def inspect_dead_letter(self, *, count: int = 50) -> dict:
        """Bounded, payload-free operator inventory with event SHA-256."""
        import hashlib
        if not 1 <= count <= 100:
            raise ValueError("inspect count must be 1..100")
        entries = self.redis.xrevrange(self.dead_letter, count=count)
        return {
            "stream": self.dead_letter,
            "depth": self.redis.xlen(self.dead_letter),
            "items": [{
                "id": msg_id,
                "source_id": fields.get("source_id", ""),
                "reason": fields.get("reason", "")[:100],
                "event_sha256": hashlib.sha256(
                    fields.get("event", "").encode("utf-8")
                ).hexdigest(),
            } for msg_id, fields in entries],
            "note": "No raw flows returned; replay needs explicit checksum approval.",
        }

    def replay_dead_letter(self, msg_id: str, *, expected_event_sha256: str,
                           allow_replay: bool = False) -> dict:
        """Explicit operator-controlled replay; no accidental drain or loss.

        The expected digest is computed/approved by the operator separately.
        This function never assumes DLQ contents are benign or safe.
        """
        import hashlib

        if not allow_replay:
            raise ValueError("Explicit replay authorization required")
        rows = self.redis.xrange(self.dead_letter, min=msg_id, max=msg_id, count=1)
        if not rows or rows[0][0] != msg_id:
            raise ValueError("DLQ entry missing")
        fields = rows[0][1]
        original = fields.get("event")
        if not isinstance(original, str) or hashlib.sha256(
            original.encode("utf-8")
        ).hexdigest() != expected_event_sha256:
            raise ValueError("DLQ event SHA256 does not match operator approval")
        from networkpulse.schemas import FlowEvent
        # Poison payloads may be permanently invalid. For those, an operator
        # must first correct/review data offline; blindly replaying is unsafe.
        FlowEvent.model_validate(json.loads(original))
        result = self.redis.eval(
            _REQUEUE_SCRIPT, 2, self.stream, self.dead_letter,
            msg_id, self.max_backlog,
        )
        if result == "BACKPRESSURE":
            raise BackpressureError("Cannot replay: live Redis queue is full")
        if not result or result == "MALFORMED":
            raise ValueError("DLQ entry missing or corrupt during atomic replay")
        return {"source_dlq_id": msg_id, "new_stream_id": str(result),
                "replayed": True, "note": "Database uniqueness handles at-least-once replay"}


def connect(url: str):
    import redis
    client = redis.Redis.from_url(url, decode_responses=True,
                                  socket_connect_timeout=5, socket_timeout=10,
                                  health_check_interval=30)
    client.ping()
    return client


def process_events(queue: FlowStream, consumer: str, *, settings, once: bool = False,
                   max_stall_seconds: float = 90.0,
                   retry_backoff_max_seconds: float = 4.0,
                   clock=None, sleeper=None, stop_requested=None,
                   metrics_port: int | None = None):
    """Supervised native scoring: preserve pending traffic and fail after stall."""
    from networkpulse.detector import Detector
    from networkpulse.schemas import FlowEvent
    from networkpulse.service import ingest
    from networkpulse.storage import build_sessions
    from networkpulse.ops_health import mark_success
    from sqlalchemy import text as sql_text
    from pathlib import Path
    from time import monotonic, sleep
    from networkpulse.streaming.worker_recovery import WorkerFailureBudget
    from networkpulse.streaming import worker_metrics

    budget = WorkerFailureBudget(
        max_stall_seconds=max_stall_seconds,
        max_backoff_seconds=retry_backoff_max_seconds,
    )
    clock = monotonic if clock is None else clock
    sleeper = sleep if sleeper is None else sleeper
    stop_requested = (lambda: False) if stop_requested is None else stop_requested
    if metrics_port is not None and not 1024 <= metrics_port <= 65535:
        raise ValueError("Invalid private worker metrics port")
    from networkpulse.deployment_preflight import require_runtime_release
    require_runtime_release(settings)
    if settings.deployment_mode == "production" and not settings.model_sha256:
        raise ValueError("Production stream worker requires MODEL_SHA256")
    if settings.model_sha256:
        from networkpulse.model_registry import sha256
        if (len(settings.model_sha256) != 64 or
                sha256(settings.model_path) != settings.model_sha256):
            raise ValueError("Trusted model artifact SHA-256 verification failed")
    detector = Detector.load(settings.model_path)
    if (settings.deployment_mode == "production" or
            os.getenv("NETWORKPULSE_MODEL_REGISTRY_ROOT")) and (
        "synthetic" in str(detector.metadata.get("source", "")).lower()
    ):
        raise ValueError("Production stream worker refuses synthetic/demo model")
    # Never create a consumer/read messages until the release is trusted.
    queue.initialize()
    maker = build_sessions(settings.database_url)
    unique_consumer = f"{consumer}:{socket.gethostname()}:{os.getpid()}"
    # Activate the exporter only after model trust and DB migration validation.
    if metrics_port is not None:
        worker_metrics.start_private_exporter(metrics_port)
    worker_metrics.WORKER_READY.set(0)

    def store_batch(events):
        with maker() as session:
            ingest(session, detector, events)

    try:
        while not stop_requested():
            def note_failure():
                worker_metrics.HANDLER_FAILURES.inc()
                worker_metrics.WORKER_READY.set(0)
                budget.record_handler_failure(clock())

            began = clock()
            outcome = queue.consume_batch_once(
                unique_consumer, store_batch, FlowEvent.model_validate,
                on_handler_failure=note_failure,
                on_committed=(lambda ids: worker_metrics.record_acknowledged(
                    queue.redis, ids)) if metrics_port is not None else None,
            )
            worker_metrics.record_cycle(outcome, clock() - began)
            if outcome["processed"]:
                # A completed DB transaction + Redis ACK is forward progress.
                budget.committed_batch()
            # An empty Redis poll DOES NOT clear a previously failed handler:
            # it might be waiting for XAUTOCLAIM's idle timeout. Neither
            # successfully reading Redis nor SELECT 1 proves that the failed
            # batch has been committed.
            budget.assert_not_expired(clock())
            if not outcome["processed"] and not outcome["retried"] and not budget.degraded:
                with maker() as session:
                    session.execute(sql_text("SELECT 1"))
            if not budget.degraded and (not outcome["retried"] or outcome["processed"]):
                mark_success(Path("/tmp/networkpulse-stream-heartbeat.json"), "stream")
                worker_metrics.WORKER_READY.set(1)
            if once:
                return outcome
            if any(outcome.values()):
                # No IPs, flow payloads or credentials in operational logs.
                print(json.dumps({"worker": "flow", **outcome}), flush=True)
            if budget.degraded:
                delay = budget.retry_delay(clock())
                if delay:
                    sleeper(delay)
                budget.assert_not_expired(clock())
    finally:
        worker_metrics.WORKER_READY.set(0)
        maker.kw["bind"].dispose()
