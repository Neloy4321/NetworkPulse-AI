"""Frozen cross-source source identity, label and adapter safety tests."""
from __future__ import annotations

from datetime import timezone

import pytest

from networkpulse.evaluation import uwf_zeek_external_frozen as uwf
from networkpulse.feature_contract_v2 import features_v2


def row(**overrides):
    base = {
        "ts": "1644537600.0", "uid": "private-uid",
        "src_ip": "192.0.2.3", "dest_ip": "198.51.100.4",
        "src_port": "53535", "dest_port": "1883", "protocol": "tcp",
        "duration": "", "orig_bytes": "", "resp_bytes": "",
        "orig_pkts": "4", "resp_pkts": "0", "conn_state": "SH",
        "mitre_attack_tactics": "Discovery",
    }
    base.update(overrides)
    return base


def test_uwf_adapts_to_canonical_leak_free_missingness_contract():
    flow = uwf.adapt_uwf_zeek(row())
    assert flow.timestamp.tzinfo == timezone.utc
    assert flow.dst_port == 1883
    assert flow.conn_state == "sh"
    assert flow.duration is None and flow.resp_bytes is None
    features = features_v2(flow)
    assert features["missing_duration"] == 1.0
    assert features["missing_resp_bytes"] == 1.0
    assert not any("private" in key or "192.0.2.3" in key for key in features)


def test_only_declared_source_labels_are_valid():
    assert uwf.producer_label("none") == 0
    assert uwf.producer_label("Discovery") == 1
    with pytest.raises(ValueError, match="Unexpected external"):
        uwf.producer_label("unverified_attack")


def test_frozen_threshold_and_immutable_source_hash():
    assert uwf.locked.CUTOFF == 0.90
    assert uwf.SAMPLE_SHA256 == "991d7cd72f299484ab2892df21a02cd838fea0dce3e92eab6a406c69f78e79c2"
    assert uwf.EXPECTED_RAW_ROWS == 10_490
    assert uwf.EXPECTED_RAW_ATTACK == 2_086
    assert "mitre_attack_tactics" not in features_v2(uwf.adapt_uwf_zeek(row()))
