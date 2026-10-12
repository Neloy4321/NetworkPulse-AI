import json
from pathlib import Path

import pytest

from networkpulse.adapters import SkipRecord, from_suricata, from_zeek, iter_jsonl


def test_zeek_conn_adapter():
    zeek = {
        "ts": 1767225600.0, "uid": "zeek-x1", "id.orig_h": "10.0.0.5",
        "id.resp_h": "1.1.1.1", "id.orig_p": 40321, "id.resp_p": 443,
        "proto": "tcp", "duration": 2.4, "orig_bytes": 513,
        "resp_bytes": 1024, "orig_pkts": 3, "resp_pkts": 4, "conn_state": "SF"
    }
    evt = from_zeek(zeek)
    assert evt.source == "zeek" and evt.conn_state == "sf"
    assert evt.dst_port == 443 and evt.resp_bytes == 1024


def test_suricata_flow_adapter():
    record = {
        "timestamp": "2026-01-01T00:00:00+00:00", "event_type": "flow", "flow_id": 155,
        "src_ip": "10.0.0.9", "dest_ip": "8.8.8.8", "src_port": 51803,
        "dest_port": 53, "proto": "UDP",
        "flow": {"age": 2, "bytes_toserver": 35, "bytes_toclient": 70,
                 "pkts_toserver": 2, "pkts_toclient": 2, "state": "established"},
    }
    evt = from_suricata(record)
    assert evt.source == "suricata" and evt.proto == "udp"
    assert evt.orig_bytes == 35 and evt.resp_bytes == 70


def test_skip_unrelated_suricata_events(tmp_path: Path):
    file = tmp_path / "suricata.jsonl"
    file.write_text(json.dumps({"event_type": "dns"}) + "\n")
    assert list(iter_jsonl(file, "suricata")) == []


def test_jsonl_error_contains_line(tmp_path: Path):
    file = tmp_path / "bad.jsonl"
    file.write_text("not valid json\n")
    with pytest.raises(ValueError, match=r"bad.jsonl:1"):
        list(iter_jsonl(file, "canonical"))
