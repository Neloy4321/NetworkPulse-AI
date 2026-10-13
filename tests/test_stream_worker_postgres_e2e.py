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
