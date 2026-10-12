"""Redis Streams queue with bounded backlog and dead-letter processing.

Delivery is at-least-once, not exactly-once. Database ON CONFLICT ensures that
replays and worker restarts do not create duplicate persisted flow alerts.
"""

from __future__ import annotations

import json
from collections.abc import Callable

STREAM = "networkpulse:flow:stream"
DLQ = "networkpulse:flow:dead_letter"
GROUP = "networkpulse-workers"


class BackpressureError(Exception):
    pass


class FlowStream:
    def __init__(self, redis_client, *, stream: str = STREAM, group: str = GROUP,
                 max_backlog: int = 50000, max_attempts: int = 5):
        if max_backlog < 100 or max_attempts < 1:
            raise ValueError("invalid Redis Streams configuration")
        self.redis = redis_client
        self.stream = stream
        self.group = group
        self.max_backlog = max_backlog
        self.max_attempts = max_attempts

    def initialize(self):
        try:
            self.redis.xgroup_create(self.stream, self.group, id="0-0", mkstream=True)
        except Exception as exc:
            # Only swallow BUSYGROUP (the consumer group already exists).
            if "BUSYGROUP" not in str(exc):
                raise

    def enqueue(self, event: dict) -> str:
        if self.redis.xlen(self.stream) >= self.max_backlog:
            raise BackpressureError("Redis backlog full; collector checkpoint must not advance")
        return self.redis.xadd(self.stream, {"event": json.dumps(event, separators=(",", ":"))})

    def _messages(self, consumer: str, block_ms: int = 1000, count: int = 25):
        result = self.redis.xreadgroup(self.group, consumer, {self.stream: ">"},
                                       count=count, block=block_ms)
        return [entry for _stream, entries in result for entry in entries]

    def _recover(self, consumer: str, idle_ms: int = 30000, count: int = 25):
        # XAUTOCLAIM available on Redis 6.2+; claim orphaned entries after crash.
        _next_id, entries, *_ = self.redis.xautoclaim(self.stream, self.group,
                                                      consumer, min_idle_time=idle_ms,
                                                      start_id="0-0", count=count)
        return entries

    def _ack(self, msg_id: str):
        # Acknowledge and delete after successful durable DB transaction.
        with self.redis.pipeline(transaction=True) as pipe:
            pipe.xack(self.stream, self.group, msg_id)
            pipe.xdel(self.stream, msg_id)
            pipe.execute()

    def _dead_letter(self, msg_id: str, fields: dict, reason: str):
        # The DLQ stores the original metadata event for authorized operators.
        with self.redis.pipeline(transaction=True) as pipe:
            pipe.xadd(DLQ, {"event": fields.get("event", ""), "source_id": msg_id,
                            "reason": reason[:256]})
            pipe.xack(self.stream, self.group, msg_id)
            pipe.xdel(self.stream, msg_id)
            pipe.execute()

    def _deliveries(self, msg_id: str) -> int:
        info = self.redis.xpending_range(self.stream, self.group, msg_id, msg_id, 1)
        return info[0].get("times_delivered", 1) if info else 1

    def consume_once(self, consumer: str, handler: Callable[[dict], None],
                     *, recover: bool = True, block_ms: int = 1000,
                     recover_idle_ms: int = 30000) -> dict:
        entries = self._recover(consumer, idle_ms=recover_idle_ms) if recover else []
        if not entries:
            entries = self._messages(consumer, block_ms=block_ms)
        out = {"processed": 0, "retried": 0, "dead_lettered": 0}
        for msg_id, fields in entries:
            try:
                payload = json.loads(fields["event"])
                handler(payload)  # MUST complete the DB transaction before returning.
            except Exception as exc:
                # Avoid storing secrets/record fields in exception logs.
                if self._deliveries(msg_id) >= self.max_attempts:
                    self._dead_letter(msg_id, fields, type(exc).__name__)
                    out["dead_lettered"] += 1
                else:
                    out["retried"] += 1  # Remains pending; reclaimed after idle_ms.
            else:
                self._ack(msg_id)
                out["processed"] += 1
        return out


def connect(url: str):
    import redis  # Optional dependency; install: pip install -e '.[streaming]'
    client = redis.Redis.from_url(url, decode_responses=True,
                                  socket_connect_timeout=5, socket_timeout=10,
                                  health_check_interval=30)
    client.ping()
    return client


def process_events(queue: FlowStream, consumer: str, *, settings, once: bool = False):
    from networkpulse.detector import Detector
    from networkpulse.schemas import FlowEvent
    from networkpulse.service import ingest
    from networkpulse.storage import build_sessions

    queue.initialize()
    detector = Detector.load(settings.model_path)
    maker = build_sessions(settings.database_url)

    def store(payload):
        validated = FlowEvent.model_validate(payload)
        with maker() as session:
            ingest(session, detector, [validated])

    try:
        while True:
            result = queue.consume_once(consumer, store)
            if once:
                return result
    finally:
        maker.kw["bind"].dispose()
