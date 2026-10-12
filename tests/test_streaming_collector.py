import json
from pathlib import Path

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
    def xlen(self, stream):return len(self.messages)
    def xadd(self, stream, fields):
        self.messages.append(fields)
        return "1-0"


def test_queue_backpressure_and_serialization():
    f=FakeRedis();q=FlowStream(f,max_backlog=100)
    data=sample_flows(100)[0].model_dump(mode="json")
    q.enqueue(data)
    assert json.loads(f.messages[0]["event"])==data
    f.messages *= 100
    with pytest.raises(BackpressureError):q.enqueue(data)
