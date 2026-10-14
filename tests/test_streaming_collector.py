import json

import pytest

from networkpulse.streaming.collector import LogCollector
from networkpulse.streaming.redis_streams import BackpressureError, FlowStream
from networkpulse.simulator import sample_flows


def test_collector_checkpoint_and_incomplete_line(tmp_path):
    events = sample_flows(100, seed=7)[:2]
    source = tmp_path/"events.jsonl"
    lines = [json.dumps(e.model_dump(mode="json")) for e in events]
    source.write_text(lines[0]+"\n"+lines[1][0:30])
    values = []
    c = LogCollector(source,"canonical",tmp_path/"offset.json", values.append)
    assert c.poll_once()["published"] == 1
    assert c.poll_once()["published"] == 0
    with source.open("a") as file:
        file.write(lines[1][30:]+"\n")
    assert c.poll_once()["published"] == 1
    assert c.poll_once()["published"] == 0
    assert len(values)==2


def test_collector_replay_only_if_checkpoint_not_committed(tmp_path):
    source=tmp_path/"e.jsonl"
    source.write_text(json.dumps(sample_flows(100)[0].model_dump(mode="json"))+"\n")
    calls=[]
    def fail_once(e):
        calls.append(e)
        if len(calls)==1:
            raise BackpressureError("busy")
    c=LogCollector(source,"canonical",tmp_path/"offset.json",fail_once)
    with pytest.raises(BackpressureError):
        c.poll_once()
    assert c.poll_once()["published"] == 1


class FakeRedis:
    def __init__(self):
        self.messages=[]
    def eval(self, _script, _keys, _stream, limit, encoded):
        if len(self.messages) >= int(limit):
            return None
        self.messages.append({"event": encoded})
        return "1-0"


def test_queue_backpressure_and_serialization():
    f=FakeRedis()
    q=FlowStream(f,max_backlog=100)
    data=sample_flows(100)[0].model_dump(mode="json")
    q.enqueue(data)
    assert json.loads(f.messages[0]["event"])==data
    f.messages *= 100
    with pytest.raises(BackpressureError):
        q.enqueue(data)


def _as_lines(events):
    return [json.dumps(e.model_dump(mode="json")) + "\n" for e in events]


def test_rename_rotation_drains_unread_old_inode_before_active_file(tmp_path):
    events = sample_flows(100, seed=2601)[:5]
    old = tmp_path / "zeek.jsonl"
    rotated = tmp_path / "zeek.jsonl.1"
    old.write_text("".join(_as_lines(events[:3])))
    collected = []
    c = LogCollector(old, "canonical", tmp_path / "checkpoint.json", collected.append)
    assert c.poll_once(max_rows=1)["published"] == 1
    old.rename(rotated)
    old.write_text("".join(_as_lines(events[3:])))
    assert c.poll_once(max_rows=2)["published"] == 2
    # The 2 remaining records from the old inode precede the new file.
    assert [v["uid"] for v in collected] == [e.uid for e in events[:3]]
    last = c.poll_once()
    assert last["published"] == 2
    assert last["rotation_recovered"] is True
    assert [v["uid"] for v in collected] == [e.uid for e in events]
    assert c.poll_once()["published"] == 0


def test_missing_rotated_inode_fails_closed_and_preserves_checkpoint(tmp_path):
    events = sample_flows(100, seed=2602)[:2]
    active = tmp_path / "sensor.jsonl"
    rotated = tmp_path / "sensor.jsonl.1"
    checkpoint = tmp_path / "checkpoint.json"
    active.write_text("".join(_as_lines(events)))
    c = LogCollector(active, "canonical", checkpoint, lambda _: None)
    assert c.poll_once(max_rows=1)["published"] == 1
    saved = checkpoint.read_bytes()
    active.rename(rotated)
    rotated.unlink()
    active.write_text("".join(_as_lines(events[1:])))
    from networkpulse.streaming.collector import ContinuityError
    with pytest.raises(ContinuityError, match="unavailable"):
        c.poll_once()
    assert checkpoint.read_bytes() == saved


def test_copytruncate_does_not_discard_unread_log(tmp_path):
    events = sample_flows(100, seed=2603)[:3]
    active = tmp_path / "sensor.jsonl"
    cp = tmp_path / "checkpoint.json"
    active.write_text("".join(_as_lines(events)))
    c = LogCollector(active, "canonical", cp, lambda _: None)
    assert c.poll_once(max_rows=2)["published"] == 2
    earlier = cp.read_bytes()
    active.write_text(_as_lines(events)[2])
    from networkpulse.streaming.collector import ContinuityError
    with pytest.raises(ContinuityError, match="truncated"):
        c.poll_once()
    assert cp.read_bytes() == earlier


def test_rotated_partial_record_fails_closed_instead_of_skipping(tmp_path):
    events = sample_flows(100, seed=2604)[:2]
    source = tmp_path / "sensor.jsonl"
    cp = tmp_path / "checkpoint.json"
    source.write_text(_as_lines(events)[0] + '{"partial":')
    c = LogCollector(source, "canonical", cp, lambda _: None)
    assert c.poll_once()["published"] == 1
    source.rename(tmp_path / "sensor.jsonl.1")
    source.write_text(_as_lines(events)[1])
    from networkpulse.streaming.collector import ContinuityError
    with pytest.raises(ContinuityError, match="incomplete"):
        c.poll_once()
    assert json.loads(cp.read_text())["offset"] == len(_as_lines(events)[0].encode())


def test_corrupted_checkpoint_never_resets_to_zero(tmp_path):
    source = tmp_path / "sensor.jsonl"
    cp = tmp_path / "checkpoint.json"
    source.write_text(_as_lines(sample_flows(100, seed=2605)[:1])[0])
    cp.write_text("{broken")
    c = LogCollector(source, "canonical", cp, lambda _: None)
    from networkpulse.streaming.collector import ContinuityError
    with pytest.raises(ContinuityError, match="corrupt"):
        c.poll_once()
    assert cp.read_text() == "{broken"


def test_sensor_log_symlink_rejected(tmp_path):
    source = tmp_path / "private.jsonl"
    source.write_text(_as_lines(sample_flows(100, seed=2606)[:1])[0])
    link = tmp_path / "link.jsonl"
    link.symlink_to(source)
    c = LogCollector(link, "canonical", tmp_path / "offset.json", lambda _: None)
    with pytest.raises(OSError):
        c.poll_once()


def test_exclusive_collector_owner_prevents_competing_polls(tmp_path):
    from networkpulse.streaming.collector import ContinuityError
    source = tmp_path / "sensor.jsonl"
    source.write_text(_as_lines(sample_flows(100, seed=2607)[:1])[0])
    c1 = LogCollector(source, "canonical", tmp_path / "offset.json", lambda _: None)
    c2 = LogCollector(source, "canonical", tmp_path / "offset.json", lambda _: None)
    with c1._ownership():
        with pytest.raises(ContinuityError, match="already owned"):
            c2.poll_once()
    assert c2.poll_once()["published"] == 1


def test_checkpoint_is_owner_only_and_persistent(tmp_path):
    import stat
    source = tmp_path / "sensor.jsonl"
    cp = tmp_path / "offset.json"
    source.write_text(_as_lines(sample_flows(100, seed=2608)[:1])[0])
    c = LogCollector(source, "canonical", cp, lambda _: None)
    assert c.poll_once()["published"] == 1
    assert stat.S_IMODE(cp.stat().st_mode) == 0o600
    assert json.loads(cp.read_text())["offset"] == source.stat().st_size


@pytest.mark.skipif(
    not __import__("os").getenv("REDIS_TEST_URL"),
    reason="Real CI Redis 7 required",
)
def test_real_redis_collector_survives_rotation_and_backpressure(tmp_path):
    import os
    import uuid
    import redis
    events = sample_flows(110, seed=2609)[:102]
    active = tmp_path / "conn.jsonl"
    active.write_text("".join(_as_lines(events)))
    client = redis.Redis.from_url(os.environ["REDIS_TEST_URL"], decode_responses=True)
    key = "networkpulse:ci:rotation:" + uuid.uuid4().hex
    queue = FlowStream(client, stream=key, group="ci-rotation", max_backlog=100)
    collector = LogCollector(active, "canonical", tmp_path / "offset.json", queue.enqueue)
    try:
        queue.initialize()
        assert collector.poll_once(max_rows=50)["published"] == 50
        active.rename(tmp_path / "conn.jsonl.1")
        active.write_text(_as_lines(events)[100] + _as_lines(events)[101])
        assert collector.poll_once(max_rows=50)["published"] == 50
        with pytest.raises(BackpressureError):
            collector.poll_once()
        assert client.xlen(key) == 100
        # Only committed queue writes may be reflected in the checkpoint.
        # The old inode has been drained; the new file is checkpointed
        # at offset zero before its first (backpressured) enqueue.
        saved = json.loads((tmp_path / "offset.json").read_text())
        assert saved["offset"] == 0
        assert saved["identity"] == [active.stat().st_dev, active.stat().st_ino]
        consumed = []

        def handler(batch):
            consumed.extend(batch)

        from networkpulse.schemas import FlowEvent
        while len(consumed) < 100:
            outcome = queue.consume_batch_once(
                "ci-rotation-drain", handler, FlowEvent.model_validate,
                recover=False, block_ms=5,
            )
            assert outcome["retried"] == outcome["dead_lettered"] == 0
        assert collector.poll_once()["published"] == 2
        assert client.xlen(key) == 2
        assert collector.poll_once()["published"] == 0
        assert len(consumed) == 100
    finally:
        client.delete(key, queue.dead_letter)
        client.close()
