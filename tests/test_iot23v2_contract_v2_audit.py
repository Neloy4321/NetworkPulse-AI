"""V2 sensor ingestion and pinned full-capture audit safety contracts."""
import json
from pathlib import Path

import pytest

from networkpulse.adapters import iter_jsonl_v2, parse, parse_v2
from networkpulse.evaluation.iot23v2_contract_v2_audit import run
from networkpulse.feature_contract_v2 import FlowV2, features_v2


def zeek_json():
    return {
        "ts": 1767225600, "uid": "fixture",
        "id.orig_h": "192.0.2.10", "id.orig_p": 50400,
        "id.resp_h": "198.51.100.10", "id.resp_p": 443,
        "proto": "tcp", "duration": "-", "orig_bytes": "-",
        "resp_bytes": 0, "orig_pkts": "3", "resp_pkts": "-",
        "conn_state": "S0",
    }


def test_v2_ingestion_keeps_missing_values_through_jsonl(tmp_path: Path):
    source = tmp_path / "captured.jsonl"
    source.write_text(json.dumps(zeek_json()) + "\n")
    records = list(iter_jsonl_v2(source, "zeek"))
    assert len(records) == 1 and isinstance(records[0], FlowV2)
    assert records[0].duration is None and records[0].resp_bytes == 0
    assert features_v2(records[0])["missing_duration"] == 1.0
    assert features_v2(records[0])["missing_resp_bytes"] == 0.0
    assert list(iter_jsonl_v2(source, "zeek"))[0] == records[0]


def test_old_ingestion_retained_without_global_flag(tmp_path: Path):
    old = parse(zeek_json(), "zeek")
    new = parse_v2(zeek_json(), "zeek")
    assert old.duration == 0
    assert new.duration is None
    assert old.orig_bytes == 0
    assert new.orig_bytes is None


def test_invalid_port_identity_is_rejected_not_imputed(tmp_path: Path):
    file = tmp_path / "bad.jsonl"
    row = zeek_json()
    row["id.resp_p"] = "-"
    file.write_text(json.dumps(row) + "\n")
    with pytest.raises(ValueError, match="bad.jsonl:1"):
        list(iter_jsonl_v2(file, "zeek"))


def test_v2_input_source_cannot_silently_become_canonical():
    record = {
        "timestamp": "2026-01-01T00:00:00+00:00", "source": "zeek",
        "src_ip": "192.0.2.10", "src_port": 30000, "dst_ip": "198.51.100.10",
        "dst_port": 443, "proto": "tcp",
    }
    with pytest.raises(ValueError, match="canonical V2"):
        parse_v2(record, "canonical")


def test_unrelated_suricata_eve_event_is_skipped(tmp_path: Path):
    path = tmp_path / "suricata.jsonl"
    path.write_text('{"event_type":"dns"}\n')
    assert list(iter_jsonl_v2(path, "suricata")) == []


def test_real_capture_audit_refuses_unpinned_or_malformed_source(tmp_path: Path):
    fake = tmp_path / "not-actual-iot23.log"
    fake.write_text("#fields\tbad\n")
    with pytest.raises(ValueError, match="SHA-256 or size mismatch"):
        run(fake)


def test_v2_model_features_do_not_emit_private_identifiers():
    features = features_v2(parse_v2(zeek_json(), "zeek"))
    forbidden = ("192.0.2.", "198.51.100.", "fixture", "S0", "zeek", "1767225600")
    encoded = json.dumps(features)
    assert not any(s in encoded for s in forbidden)
