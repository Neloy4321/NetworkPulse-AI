"""Leakage, eligibility and diagnostic-scope controls for MQTT feature repair."""
from __future__ import annotations

from datetime import datetime, timezone

import numpy as np

from networkpulse.evaluation import iot_sfc_mqtt_repair as repair
from networkpulse.feature_contract_v2 import FlowV2


def sample(*, dst_port=1883, conn_state="SH") -> FlowV2:
    return FlowV2(
        timestamp=datetime(2025, 4, 15, tzinfo=timezone.utc), source="zeek",
        uid="secret-uid", src_ip="192.0.2.8", dst_ip="198.51.100.2",
        src_port=53535, dst_port=dst_port, proto="tcp",
        duration=1.1, orig_bytes=150, resp_bytes=None,
        orig_pkts=3, resp_pkts=1, conn_state=conn_state,
    )


def test_research_features_preserve_v2_missingness_and_add_stable_signals():
    f = repair.features_repair(sample())
    assert f["missing_resp_bytes"] == 1.0
    assert f["research_service=port_1883"] == 1.0
    assert f["research_state=sh"] == 1.0
    assert not any("secret" in k or "192.0.2.8" in k for k in f)


def test_unknown_service_state_are_bounded():
    f = repair.features_repair(sample(dst_port=31337, conn_state="ODD_CUSTOM_STATE"))
    assert f["research_service=other_registered"] == 1.0
    assert f["research_state=other"] == 1.0


def test_too_few_group_disjoint_dev_attacks_cannot_qualify():
    result = repair.candidate_selection({"extra": np.ones(199)}, np.zeros(199, dtype=int))
    assert result["selected"] is None
    assert result["reason"] == "GROUP_DISJOINT_DEV_UNDERPOWERED"


def test_dev_selection_uses_joint_wilson_gates():
    y = np.r_[np.zeros(1000, dtype=np.int8), np.ones(200, dtype=np.int8)]
    scores = np.r_[np.full(1000, 0.01), np.full(200, 0.95)]
    result = repair.candidate_selection({"new": scores}, y)
    assert result["selected"] is not None
    assert result["selected"]["eligible"] is True
    assert result["selected"]["fpr_upper95"] <= 0.03
    assert result["selected"]["recall_lower95"] >= 0.8


def test_source_family_is_small_approved_taxonomy():
    assert repair.family({"type_of_attack": "MQTT_MALFORMED"}) == "mqtt_malformed"
    assert repair.family({"type_of_attack": "1.2.3.4"}) == "other_attack_family"


def test_source_dev_error_profile_is_aggregate_only():
    benign = sample(dst_port=1883, conn_state="S0")
    attack = sample(dst_port=80, conn_state="SF")
    flows = [benign, attack]
    result = repair.source_dev_error_profile(
        flows, np.array([0, 1]), ["benign", "mqtt_malformed"],
        [0, 1], np.array([0.99, 0.12]), 0.80,
    )
    assert result["false_positives"]["count"] == 1
    assert result["false_positives"]["by_service"] == {"1883": 1}
    assert result["false_negatives"]["by_producer_attack_family"] == {
        "mqtt_malformed": 1,
    }
    assert result["false_positives"]["distinct_groups"] == 1
    assert "192.0.2.8" not in str(result)
    assert "secret-uid" not in str(result)


def test_no_new_holdout_or_release_in_research_module():
    assert repair.FIT_LAST_DAY < repair.DEV_DAY < repair.locked.TEST_DAYS[0]
    assert "signed" not in repair.features_repair(sample())
