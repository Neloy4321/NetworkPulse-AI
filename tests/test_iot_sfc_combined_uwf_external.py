"""Source-independent OR scoring input and label guards."""
from __future__ import annotations

import pytest

from networkpulse.evaluation import iot_sfc_combined_uwf_external as external
from networkpulse.feature_contract_v2 import features_v2


def test_external_adaptation_preserves_missingness_and_excludes_label_feature():
    flow = external.adapt_record({
        "ts": "1644537600.0", "uid": "private-uid",
        "src_ip": "192.0.2.1", "dest_ip": "198.51.100.1",
        "src_port": "45000", "dest_port": "1883", "protocol": "tcp",
        "duration": "", "orig_bytes": "", "resp_bytes": "",
        "orig_pkts": "1", "resp_pkts": "0", "conn_state": "S0",
        "mitre_attack_tactics": "Discovery",
    })
    assert flow.duration is None
    assert flow.dst_port == 1883
    features = features_v2(flow)
    assert features["missing_duration"] == 1.0
    assert not any("Discovery" in key or "192.0.2.1" in key for key in features)


def test_external_label_taxonomy_is_closed():
    assert external.read_label("none") == 0
    assert external.read_label("Discovery") == 1
    with pytest.raises(ValueError):
        external.read_label("unverified_attack")


def test_pinned_external_source_and_old_model_contract():
    assert external.SHA == "991d7cd72f299484ab2892df21a02cd838fea0dce3e92eab6a406c69f78e79c2"
    assert external.locked.MODEL_SHA == "ecc320bc693481fc45b143b48ffbebcb117899e888e4687930f3361501af6fa1"
    assert external.locked.CUTOFF == 0.90
