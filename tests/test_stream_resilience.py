"""Real Redis 7 transport safety, concurrency and lifecycle integration gates."""
import os
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from networkpulse.schemas import FlowEvent
from networkpulse.streaming.redis_streams import (
    BackpressureError, FlowStream,
)
from networkpulse.simulator import sample_flows


@pytest.mark.skipif(not os.getenv("REDIS_TEST_URL"), reason="CI Redis required")
def test_atomic_backlog_under_concurrent_producers():
    """Multiple collectors cannot pass a racy XLEN/XADD check."""
    import redis

    redis_url = os.environ["REDIS_TEST_URL"]
    stream = "networkpulse:ci:atomic:" + uuid.uuid4().hex
    admin = redis.Redis.from_url(redis_url, decode_responses=True)
    queue = FlowStream(admin, stream=stream, group="ci", max_backlog=100)
    flow = sample_flows(100, seed=50)[0].model_dump(mode="json")
    try:
        queue.initialize()

        def push(_):
            # Separate connections as on independent production collectors.
            client = redis.Redis.from_url(redis_url, decode_responses=True)
            try:
                return bool(FlowStream(
                    client, stream=stream, group="ci", max_backlog=100
                ).enqueue(flow))
            except BackpressureError:
                return False
            finally:
                client.close()

        with ThreadPoolExecutor(max_workers=12) as executor:
            accepted = list(executor.map(push, range(170)))
        assert sum(accepted) == 100
        assert len(accepted) - sum(accepted) == 70
        assert admin.xlen(stream) == 100
        # No producer could make the stream grow past the advertised cap.
        with pytest.raises(BackpressureError):
            queue.enqueue(flow)
        assert admin.xlen(stream) == 100
    finally:
        admin.delete(stream, queue.dead_letter)
        admin.close()


@pytest.mark.skipif(not os.getenv("REDIS_TEST_URL"), reason="CI Redis required")
def test_transient_database_outage_retains_pending_and_mixed_poison_isolated():
    import redis

    client = redis.Redis.from_url(os.environ["REDIS_TEST_URL"], decode_responses=True)
    stream = "networkpulse:ci:outage:" + uuid.uuid4().hex
    queue = FlowStream(client, stream=stream, group="ci", max_backlog=100,
                       max_attempts=2)
    events = sample_flows(100, seed=51)
    valid = [event.model_dump(mode="json") for event in events[:3]]
    try:
        queue.initialize()
        for item in valid:
            queue.enqueue(item)
        queue.enqueue({"malformed": "missing_required_flow_fields"})
        processed = []

        def db_offline(_):
            raise ConnectionError("database-unavailable-test-only")

        # First read: one schema poison, three legitimate flows.
        failed = queue.consume_batch_once(
            "worker-a", db_offline, FlowEvent.model_validate,
            recover=False, block_ms=5,
        )
        assert failed == {"processed": 0, "retried": 4, "dead_lettered": 0}
        assert client.xlen(stream) == 4
        assert client.xlen(queue.dead_letter) == 0
        # A recovered batch fails again. Despite max_attempts=2, an outage
        # must NEVER send valid events to DLQ.
        again = queue.consume_batch_once(
            "worker-b", db_offline, FlowEvent.model_validate,
            recover=True, recover_idle_ms=0, block_ms=5,
        )
        assert again == {"processed": 0, "retried": 3, "dead_lettered": 1}
        assert client.xlen(queue.dead_letter) == 1
        assert client.xlen(stream) == 3
        assert client.xpending(stream, "ci")["pending"] == 3

        restored = queue.consume_batch_once(
            "worker-c", lambda batch: processed.extend(batch),
            FlowEvent.model_validate,
            recover=True, recover_idle_ms=0, block_ms=5,
        )
        assert restored["processed"] == 3
        assert len(processed) == 3
        assert all(isinstance(item, FlowEvent) for item in processed)
        assert client.xlen(stream) == 0
        assert client.xpending(stream, "ci")["pending"] == 0
    finally:
        client.delete(stream, queue.dead_letter)
        client.close()


@pytest.mark.skipif(not os.getenv("REDIS_TEST_URL"), reason="CI Redis required")
def test_operator_approved_dead_letter_replay_is_atomic_and_auditable():
    import redis

    client = redis.Redis.from_url(os.environ["REDIS_TEST_URL"], decode_responses=True)
    stream = "networkpulse:ci:operator:" + uuid.uuid4().hex
    queue = FlowStream(client, stream=stream, group="ci", max_backlog=100,
                       max_attempts=2)
    flow = sample_flows(100, seed=52)[0].model_dump(mode="json")
    try:
        queue.initialize()
        queue.enqueue(flow)
        for _ in range(2):
            queue.consume_once(
                "worker-ci", lambda _p: (_ for _ in ()).throw(ValueError("poison")),
                recover=True, recover_idle_ms=0, block_ms=5,
            )
        inventory = queue.inspect_dead_letter()
        assert inventory["depth"] == 1
        assert len(inventory["items"]) == 1
        assert "src_ip" not in str(inventory)
        item = inventory["items"][0]
        with pytest.raises(ValueError, match="authorization"):
            queue.replay_dead_letter(
                item["id"], expected_event_sha256=item["event_sha256"])
        with pytest.raises(ValueError, match="SHA256"):
            queue.replay_dead_letter(
                item["id"], expected_event_sha256="0"*64, allow_replay=True)
        result = queue.replay_dead_letter(
            item["id"], expected_event_sha256=item["event_sha256"],
            allow_replay=True,
        )
        assert result["replayed"]
        assert client.xlen(queue.dead_letter) == 0
        assert client.xlen(stream) == 1
        seen = []
        assert queue.consume_batch_once(
            "restored", lambda events: seen.extend(events),
            FlowEvent.model_validate, recover=False, block_ms=5,
        )["processed"] == 1
        assert seen[0].src_ip == FlowEvent.model_validate(flow).src_ip
        assert client.xlen(stream) == 0
    finally:
        client.delete(stream, queue.dead_letter)
        client.close()


@pytest.mark.skipif(not os.getenv("REDIS_TEST_URL"), reason="CI Redis required")
def test_dead_letter_storage_failure_never_acknowledges_or_deletes_source():
    """Redis MULTI cannot roll back partial runtime errors; Lua ordering does."""
    import redis

    client = redis.Redis.from_url(os.environ["REDIS_TEST_URL"], decode_responses=True)
    stream = "networkpulse:ci:dlq-failure:" + uuid.uuid4().hex
    queue = FlowStream(client, stream=stream, group="ci", max_backlog=100,
                       max_attempts=2)
    try:
        queue.initialize()
        queue.enqueue({"bad_record": True})
        failed = queue.consume_batch_once(
            "ci-a", lambda _: None, FlowEvent.model_validate,
            recover=False, block_ms=5,
        )
        assert failed["retried"] == 1
        # Force a wrong-type error in destination DLQ (e.g. operator
        # accidentally overwrote the DLQ stream with a Redis string).
        client.set(queue.dead_letter, "wrongtype")
        with pytest.raises(redis.exceptions.ResponseError):
            queue.consume_batch_once(
                "ci-b", lambda _: None, FlowEvent.model_validate,
                recover=True, recover_idle_ms=0, block_ms=5,
            )
        assert client.xlen(stream) == 1
        assert client.xpending(stream, "ci")["pending"] == 1
        client.delete(queue.dead_letter)
        restored = queue.consume_batch_once(
            "ci-c", lambda _: None, FlowEvent.model_validate,
            recover=True, recover_idle_ms=0, block_ms=5,
        )
        assert restored["dead_lettered"] == 1
        assert client.xlen(stream) == 0
        assert client.xlen(queue.dead_letter) == 1
    finally:
        client.delete(stream, queue.dead_letter)
        client.close()


@pytest.mark.skipif(not os.getenv("REDIS_TEST_URL"), reason="CI Redis required")
def test_missing_batch_ack_is_rejected_before_any_ack():
    """A missing/duplicate ID must never partially ACK other pending flows."""
    import redis
    client = redis.Redis.from_url(os.environ["REDIS_TEST_URL"], decode_responses=True)
    stream = "networkpulse:ci:ack-integrity:" + uuid.uuid4().hex
    queue = FlowStream(client, stream=stream, group="ci", max_backlog=100)
    try:
        queue.initialize()
        for flow in sample_flows(100, seed=1711)[:2]:
            queue.enqueue(flow.model_dump(mode="json"))
        rows = queue._entries("ack-investigation", recover=False, block_ms=5)
        ids = [entry[0] for entry in rows]
        assert len(ids) == 2
        with pytest.raises(redis.exceptions.ResponseError, match="ACK_COUNT_MISMATCH"):
            queue._ack_many([ids[0], "0-0"])
        with pytest.raises(redis.exceptions.ResponseError, match="DUPLICATE_ACK_ID"):
            queue._ack_many([ids[0], ids[0]])
        assert client.xlen(stream) == 2
        assert client.xpending(stream, "ci")["pending"] == 2
        queue._ack_many(ids)
        assert client.xlen(stream) == 0
        assert client.xpending(stream, "ci")["pending"] == 0
    finally:
        client.delete(stream, queue.dead_letter)
        client.close()


@pytest.mark.skipif(not os.getenv("REDIS_TEST_URL"), reason="CI Redis required")
def test_dlq_transfer_rejects_nonpending_source_without_creating_duplicate():
    """An already-ACKed source cannot create an orphaned dead-letter copy."""
    import redis
    client = redis.Redis.from_url(os.environ["REDIS_TEST_URL"], decode_responses=True)
    stream = "networkpulse:ci:dlq-integrity:" + uuid.uuid4().hex
    queue = FlowStream(client, stream=stream, group="ci", max_backlog=100)
    try:
        queue.initialize()
        queue.enqueue({"invalid": "schema"})
        msg_id, fields = queue._entries("dlq-investigation", recover=False, block_ms=5)[0]
        assert client.xack(stream, "ci", msg_id) == 1
        with pytest.raises(redis.exceptions.ResponseError, match="DLQ_SOURCE_NOT_PENDING"):
            queue._dead_letter(msg_id, fields, "InvalidSchema")
        assert client.xlen(queue.dead_letter) == 0
        assert client.xlen(stream) == 1
    finally:
        client.delete(stream, queue.dead_letter)
        client.close()


@pytest.mark.skipif(not os.getenv("REDIS_TEST_URL"), reason="CI Redis required")
def test_oldest_redis_message_age_is_bounded_and_payload_free():
    import redis
    from networkpulse.streaming.monitoring import stream_snapshot

    client = redis.Redis.from_url(os.environ["REDIS_TEST_URL"], decode_responses=True)
    stream = "networkpulse:ci:flow-age:" + uuid.uuid4().hex
    queue = FlowStream(client, stream=stream, group="ci", max_backlog=100)
    try:
        queue.initialize()
        empty = stream_snapshot(client, stream=stream, group="ci",
                                dead_letter=queue.dead_letter)
        assert empty["oldest_age_seconds"] == 0.0
        queue.enqueue({"payload": "private-not-to-be-exposed"})
        observed = stream_snapshot(client, stream=stream, group="ci",
                                   dead_letter=queue.dead_letter)
        assert observed["stream_depth"] == 1
        assert observed["oldest_age_seconds"] is not None
        assert observed["oldest_age_seconds"] >= 0
        assert "private-not-to-be-exposed" not in str(observed)
    finally:
        client.delete(stream, queue.dead_letter)
        client.close()


def test_worker_idle_probe_fails_closed_on_database_outage(monkeypatch, app_settings):
    """No pending flow is required for PostgreSQL outage to break worker health."""
    from contextlib import nullcontext
    from types import SimpleNamespace
    from networkpulse.streaming.redis_streams import process_events

    class EmptyQueue:
        def initialize(self):
            pass

        def consume_batch_once(self, *_args, **_kwargs):
            return {"processed": 0, "retried": 0, "dead_lettered": 0}

    class OfflineSession:
        def execute(self, _query):
            raise ConnectionError("postgres outage injected")

    class OfflineMaker:
        kw = {"bind": SimpleNamespace(dispose=lambda: None)}

        def __call__(self):
            return nullcontext(OfflineSession())

    heartbeats = []
    monkeypatch.setattr("networkpulse.storage.build_sessions", lambda _url: OfflineMaker())
    monkeypatch.setattr("networkpulse.ops_health.mark_success",
                        lambda *args: heartbeats.append(args))
    with pytest.raises(ConnectionError, match="postgres outage injected"):
        process_events(EmptyQueue(), "fault-probe", settings=app_settings, once=True)
    assert heartbeats == []
