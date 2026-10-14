"""Real Redis -> worker -> model scoring -> PostgreSQL integration in CI.

Requires isolated CI services; uses a generated synthetic flow and temporary
model artifact. Never contacts external sensors or production databases.
"""

import os
import uuid

import pytest
from sqlalchemy import select

from networkpulse.config import Settings
from networkpulse.detector import train
from networkpulse.migrations import upgrade_database
from networkpulse.simulator import sample_flows
from networkpulse.storage import NetworkEvent, build_sessions
from networkpulse.streaming.redis_streams import FlowStream, process_events


@pytest.mark.skipif(
    not (os.getenv("REDIS_TEST_URL") and os.getenv("PG_TEST_DATABASE_URL")),
    reason="PostgreSQL and Redis isolated CI services required",
)
def test_redis_to_postgres_ack_and_idempotent_replay(tmp_path):
    import redis

    db_url = os.environ["PG_TEST_DATABASE_URL"]
    redis_url = os.environ["REDIS_TEST_URL"]
    upgrade_database(db_url)
    samples = sample_flows(300, seed=736)
    model_path = tmp_path / "worker-test-model.joblib"
    train(samples, seed=736).save(model_path)
    settings = Settings(
        database_url=db_url, model_path=model_path, api_key="ci-test-key-strong-and-long"
    )
    event = sample_flows(100, seed=9137)[-1]
    client = redis.Redis.from_url(redis_url, decode_responses=True)
    stream = "networkpulse:ci:worker:" + uuid.uuid4().hex
    group = "ci-worker-group"
    q = FlowStream(client, stream=stream, group=group, max_backlog=100)
    maker = build_sessions(db_url)
    try:
        q.initialize()
        with maker() as session:
            assert session.get(NetworkEvent, event.key()) is None

        for attempt in range(2):
            q.enqueue(event.model_dump(mode="json"))
            result = process_events(q, "ci-worker", settings=settings, once=True)
            assert result == {"processed": 1, "retried": 0, "dead_lettered": 0}
            assert client.xlen(stream) == 0
            assert client.xpending(stream, group)["pending"] == 0
            with maker() as session:
                record = session.get(NetworkEvent, event.key())
                assert record is not None
                assert record.source == "simulator"
                assert 0 <= record.risk <= 100
                assert len(session.scalars(select(NetworkEvent).where(
                    NetworkEvent.id == event.key()
                )).all()) == 1
    finally:
        maker.kw["bind"].dispose()
        client.delete(stream)
        client.close()


@pytest.mark.skipif(
    not (os.getenv("REDIS_TEST_URL") and os.getenv("PG_TEST_DATABASE_URL")),
    reason="PostgreSQL and Redis isolated CI services required",
)
def test_concurrent_stream_batches_to_postgres_without_loss_or_replay():
    """Bounded integration throughput: real Redis/PG, actual native scorer."""
    import time
    from statistics import median
    from networkpulse.schemas import FlowEvent
    from networkpulse.service import ingest

    url = os.environ["PG_TEST_DATABASE_URL"]
    upgrade_database(url)
    model_training = sample_flows(320, seed=6401)
    model = train(model_training, seed=6401)
    events = sample_flows(340, seed=6402)[:300]
    redis_client = __import__("redis").Redis.from_url(
        os.environ["REDIS_TEST_URL"], decode_responses=True,
    )
    stream = "networkpulse:ci:batch-perf:" + uuid.uuid4().hex
    queue = FlowStream(redis_client, stream=stream, group="ci", max_backlog=350)
    maker = build_sessions(url)
    durations = []
    try:
        queue.initialize()
        for event in events:
            queue.enqueue(event.model_dump(mode="json"))
        assert redis_client.xlen(stream) == len(events)
        total = 0
        started = time.perf_counter()
        while total < len(events):
            before = time.perf_counter()
            def commit_batch(batch):
                with maker() as session:
                    return ingest(session, model, batch)

            receipt = queue.consume_batch_once(
                "ci-batch-performance", commit_batch, FlowEvent.model_validate,
                recover=False, block_ms=10,
            )
            assert receipt["retried"] == receipt["dead_lettered"] == 0
            assert receipt["processed"] > 0
            total += receipt["processed"]
            durations.append(time.perf_counter() - before)
        elapsed = max(time.perf_counter() - started, 0.000001)
        assert total == len(events)
        assert redis_client.xlen(stream) == 0
        assert redis_client.xpending(stream, "ci")["pending"] == 0
        with maker() as session:
            ids = [event.key() for event in events]
            persisted = session.scalars(
                select(NetworkEvent).where(NetworkEvent.id.in_(ids))
            ).all()
            assert len(persisted) == len(events)
        print({
            "integration": "real Redis 7 -> native model -> PostgreSQL 16",
            "verified_flow_count": total,
            "committed_batches": len(durations),
            "flows_per_second_observed": round(total / elapsed, 2),
            "batch_latency_median_ms": round(median(durations) * 1000, 2),
            "batch_latency_max_ms": round(max(durations) * 1000, 2),
            "note": "CI host-only, not a production site SLO",
        })
    finally:
        maker.kw["bind"].dispose()
        redis_client.delete(stream, queue.dead_letter)
        redis_client.close()


@pytest.mark.skipif(
    not (os.getenv("REDIS_TEST_URL") and os.getenv("PG_TEST_DATABASE_URL")),
    reason="PostgreSQL and Redis isolated CI services required",
)
def test_burst_pipeline_survives_transient_commit_failure_and_drains_exactly_once():
    """Real Redis/PG, actual model scoring, ACK safety and recovery under a burst.

    This is a reproducible functional/load observation, not an external-site SLO.
    """
    import time
    from statistics import median
    import redis
    from networkpulse.schemas import FlowEvent
    from networkpulse.service import ingest
    from networkpulse.streaming.monitoring import stream_snapshot

    db_url = os.environ["PG_TEST_DATABASE_URL"]
    upgrade_database(db_url)
    model = train(sample_flows(400, seed=1901), seed=1901)
    flows = sample_flows(1100, seed=1902)[:1000]
    unique_ids = {event.key() for event in flows}
    client = redis.Redis.from_url(
        os.environ["REDIS_TEST_URL"], decode_responses=True,
    )
    stream = "networkpulse:ci:burst-recovery:" + uuid.uuid4().hex
    queue = FlowStream(client, stream=stream, group="ci", max_backlog=1500)
    maker = build_sessions(db_url)
    fault_once = {"outage": True}
    try:
        queue.initialize()
        for event in flows:
            queue.enqueue(event.model_dump(mode="json"))

        def commit(batch):
            if fault_once["outage"]:
                fault_once["outage"] = False
                raise ConnectionError("injected transient commit failure")
            with maker() as session:
                ingest(session, model, batch)

        failed = queue.consume_batch_once(
            "crash-before-commit", commit, FlowEvent.model_validate,
            recover=False, block_ms=5,
        )
        assert failed["retried"] > 0
        assert failed["processed"] == failed["dead_lettered"] == 0
        assert client.xlen(stream) == len(flows)
        assert client.xpending(stream, "ci")["pending"] == failed["retried"]
        durations = []
        accepted = 0
        start = time.perf_counter()
        for _ in range(100):
            step = time.perf_counter()
            result = queue.consume_batch_once(
                "restarted-worker", commit, FlowEvent.model_validate,
                recover=True, recover_idle_ms=0, block_ms=5,
            )
            assert result["retried"] == result["dead_lettered"] == 0
            accepted += result["processed"]
            if result["processed"]:
                durations.append(time.perf_counter() - step)
            if accepted == len(flows):
                break
        elapsed = time.perf_counter() - start
        assert accepted == len(flows), "Backlog failed to drain after worker recovery"
        assert client.xlen(stream) == 0
        assert client.xpending(stream, "ci")["pending"] == 0
        assert client.xlen(queue.dead_letter) == 0
        assert stream_snapshot(client, stream=stream, group="ci",
                               dead_letter=queue.dead_letter)["oldest_age_seconds"] == 0
        with maker() as session:
            stored = set(session.scalars(
                select(NetworkEvent.id).where(NetworkEvent.id.in_(unique_ids))
            ))
            assert stored == unique_ids

        ordered = sorted(durations)
        idx = max(0, min(len(ordered) - 1, int(len(ordered) * .95 + .999999) - 1))
        print({
            "scope": "CI Redis and PostgreSQL, not field/production SLO",
            "committed_flows": accepted,
            "unique_persisted_flows": len(stored),
            "committed_batches": len(durations),
            "elapsed_seconds": round(elapsed, 3),
            "observed_flows_per_second": round(accepted / max(elapsed, 1e-9), 1),
            "batch_latency_median_ms": round(median(durations) * 1000, 2),
            "batch_latency_p95_ms": round(ordered[idx] * 1000, 2),
        })
    finally:
        maker.kw["bind"].dispose()
        client.delete(stream, queue.dead_letter)
        client.close()


@pytest.mark.skipif(
    not (os.getenv("REDIS_TEST_URL") and os.getenv("PG_TEST_DATABASE_URL")),
    reason="Isolated PostgreSQL and Redis services required",
)
def test_sustained_worker_failure_stops_without_ack_or_dlq_then_recovers(tmp_path, monkeypatch):
    """Real Redis/Postgres state with a failing transaction handler and restart.

    Simulates a prolonged service exception without destroying the shared CI DB
    service. Failure duration is virtual; queue and SQL operations are real.
    """
    import redis
    from networkpulse.schemas import FlowEvent
    from networkpulse.service import ingest as actual_ingest
    from networkpulse.storage import build_sessions
    from networkpulse.streaming.worker_recovery import WorkerStalledError

    db_url = os.environ["PG_TEST_DATABASE_URL"]
    upgrade_database(db_url)
    model = train(sample_flows(310, seed=2820), seed=2820)
    model_file = tmp_path / "signed-independent-not-required-in-dev.joblib"
    model.save(model_file)
    settings = Settings(
        database_url=db_url, model_path=model_file,
        api_key="local-ci-key-strong-enough",
    )
    events = sample_flows(150, seed=2821)[:30]
    client = redis.Redis.from_url(
        os.environ["REDIS_TEST_URL"], decode_responses=True,
    )
    stream = "networkpulse:ci:supervised-recovery:" + uuid.uuid4().hex
    queue = FlowStream(client, stream=stream, group="ci", max_backlog=100)
    maker = build_sessions(db_url)
    from networkpulse import service
    def unavailable(_session, _model, _events):
        raise ConnectionError("simulated transient PostgreSQL handler outage")

    ticks = [0.]
    def advance(seconds):
        ticks[0] += max(seconds, 4)

    try:
        queue.initialize()
        for item in events:
            queue.enqueue(item.model_dump(mode="json"))
        monkeypatch.setattr(service, "ingest", unavailable)
        with pytest.raises(WorkerStalledError, match="stalled"):
            process_events(
                queue, "ci-unavailable", settings=settings,
                clock=lambda: ticks[0], sleeper=advance,
                max_stall_seconds=30, retry_backoff_max_seconds=2,
            )
        # The supervisor MUST NOT ACK, delete, poison-DLQ or truncate data.
        assert client.xlen(stream) == len(events)
        assert client.xlen(queue.dead_letter) == 0
        assert client.xpending(stream, "ci")["pending"] > 0

        monkeypatch.setattr(service, "ingest", actual_ingest)
        def store(batch):
            with maker() as session:
                actual_ingest(session, model, batch)

        committed = 0
        for _ in range(10):
            step = queue.consume_batch_once(
                "ci-restarted-worker", store, FlowEvent.model_validate,
                recover=True, recover_idle_ms=0, block_ms=5,
            )
            assert step["retried"] == step["dead_lettered"] == 0
            committed += step["processed"]
            if committed == len(events):
                break
        assert committed == len(events)
        assert client.xlen(stream) == 0
        assert client.xpending(stream, "ci")["pending"] == 0
        with maker() as session:
            found = set(session.scalars(
                select(NetworkEvent.id).where(
                    NetworkEvent.id.in_([event.key() for event in events])
                )
            ))
            assert found == {event.key() for event in events}
    finally:
        maker.kw["bind"].dispose()
        client.delete(stream, queue.dead_letter)
        client.close()
