"""Real Redis 7 Streams integration; skipped without isolated CI Redis service."""

import os
import uuid

import pytest

from networkpulse.streaming.redis_streams import FlowStream
from networkpulse.simulator import sample_flows


@pytest.mark.skipif(not os.getenv("REDIS_TEST_URL"), reason="No Redis integration service")
def test_redis_group_ack_retry_and_deadletter():
    import redis

    client=redis.Redis.from_url(os.environ["REDIS_TEST_URL"],decode_responses=True)
    stream="networkpulse:ci:"+uuid.uuid4().hex
    q=FlowStream(client,stream=stream,group="ci",max_backlog=100,max_attempts=2)
    try:
        q.initialize()
        q.initialize()
        flow=sample_flows(100)[0].model_dump(mode="json")
        q.enqueue(flow)
        seen=[]
        r=q.consume_once("worker-ci",lambda payload:seen.append(payload),recover=False,block_ms=10)
        assert r["processed"]==1 and seen==[flow]
        assert client.xlen(stream)==0

        q.enqueue(flow)
        r=q.consume_once("worker-ci",lambda p: (_ for _ in ()).throw(ValueError("replay")),recover=False,block_ms=10)
        assert r["retried"]==1
        # Redis XAUTOCLAIM increments delivery counter, leading to DLQ after retries.
        r=q.consume_once("worker-ci",lambda p: (_ for _ in ()).throw(ValueError("repeat")),recover=True,block_ms=10)
        assert r["dead_lettered"]==1
        assert client.xlen(stream)==0
    finally:
        client.delete(stream)
