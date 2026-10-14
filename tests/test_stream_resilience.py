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
