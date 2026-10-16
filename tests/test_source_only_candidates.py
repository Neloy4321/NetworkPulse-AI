"""Safety and reproducibility tests for predeclared source-only candidates."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from networkpulse.evaluation.source_only_candidates import (
    CANDIDATES, ESTIMATOR, FIXED_CUTOFF, candidate_features,
    fit_and_evaluate, run,
)
from networkpulse.evaluation.source_only_feature_audit import source_only_grouped_split
from networkpulse.schemas import FlowEvent


def flow(i: int, *, label: str | None = None, port: int | None = None) -> FlowEvent:
    return FlowEvent(
        timestamp=datetime.fromtimestamp(1400000000 + i, timezone.utc),
        source="canonical",
        src_ip=f"198.51.100.{1 + i % 250}",
        dst_ip=f"203.0.113.{1 + i // 250}",
        src_port=10000 + i % 20000,
        dst_port=443 if port is None else port,
        proto="tcp" if i % 2 == 0 else "udp",
        duration=float(1 + i % 50),
        orig_bytes=100 + i * 3,
        resp_bytes=80 + 2 * i,
        orig_pkts=2 + i % 50,
        resp_pkts=2 + i % 40,
        conn_state="sf" if i % 2 == 0 else "s0",
        label=label or ("benign" if i % 2 else "anomaly"),
    )


def test_port_bucketing_boundaries_and_sensor_state_ablation():
    expected = [
        (0, "well_known"), (1023, "well_known"),
        (1024, "registered"), (49151, "registered"),
        (49152, "dynamic"), (65535, "dynamic"),
    ]
    for index, (port, group) in enumerate(expected):
        event = flow(index, port=port)
        features = candidate_features(event, "rf_supervised_port_buckets_no_state")
        assert features[f"port_class={group}"] == 1.0
        assert len([k for k in features if k.startswith("port_class=")]) == 1
        assert not any(k.startswith("state=") for k in features)
        assert "dst_port" not in features
        assert "dst_is_well_known" not in features
        assert "log_bytes_per_second" in features
        assert "proto=tcp" in features or "proto=udp" in features


def test_v1_keeps_deployed_feature_contract_unchanged():
    event = flow(10)
    v1 = candidate_features(event, "rf_supervised_v1")
    assert "dst_port" in v1
    assert "dst_is_well_known" in v1
    assert "state=sf" in v1


def test_candidate_contracts_never_take_labels_or_identifiers():
    a = flow(15, label="benign")
    b = a.model_copy(update={"label": "anomaly"})
    for candidate in CANDIDATES:
        x = candidate_features(a, candidate)
        assert x == candidate_features(b, candidate)
        assert not any(key in x for key in (
            "label", "uid", "timestamp", "src_ip", "dst_ip"
        ))


def test_unregistered_candidate_fails_closed():
    with pytest.raises(ValueError, match="unknown or unregistered"):
        candidate_features(flow(1), "label_aware_threshold_steering")


def test_estimator_and_cutoff_are_frozen_before_development():
    assert CANDIDATES == (
        "rf_supervised_v1", "rf_supervised_port_buckets_no_state"
    )
    assert ESTIMATOR["n_estimators"] == 160
    assert ESTIMATOR["max_depth"] == 12
    assert ESTIMATOR["class_weight"] == "balanced_subsample"
    assert FIXED_CUTOFF == 0.5


def test_both_supervised_research_candidates_scored_without_production_promotion():
    events = [flow(i) for i in range(1600)]
    fit, dev, _, _ = source_only_grouped_split(events)
    for candidate in CANDIDATES:
        result = fit_and_evaluate(fit, dev, candidate=candidate)
        assert result["status"] == "same_source_grouped_development_only_not_acceptance"
        assert result["dev_labels_used_for_fit_or_threshold"] is False
        assert result["group_disjoint"] is True
        assert result["training_class_counts"]["benign"] >= 100
        assert result["training_class_counts"]["anomaly"] >= 100
        assert result["development_class_counts"]["benign"] >= 100
        assert result["development_class_counts"]["anomaly"] >= 100
        assert "operational_gate" not in result["evaluation"]
        assert sum(result["evaluation"]["confusion_matrix"].values()) == len(dev)
        assert result["fixed_probability_cutoff"] == 0.5
        assert "198.51.100." not in json.dumps(result)


def test_fails_on_group_overlap_even_with_different_row_keys():
    events = [flow(i) for i in range(1600)]
    fit, dev, _, _ = source_only_grouped_split(events)
    extra = fit[0].model_copy(update={"timestamp": fit[0].timestamp.replace(year=2016)})
    with pytest.raises(ValueError, match="host-pair/protocol group overlap"):
        fit_and_evaluate(fit, dev + [extra], candidate=CANDIDATES[0])


def test_fails_when_genuine_attack_labels_missing_in_fit_or_dev():
    events = [flow(i) for i in range(1600)]
    fit, dev, _, _ = source_only_grouped_split(events)
    benign_dev = [e.model_copy(update={"label": "benign"}) for e in dev]
    with pytest.raises(ValueError, match=">=100 per class"):
        fit_and_evaluate(fit, benign_dev, candidate=CANDIDATES[0])


def test_pinned_real_source_required(tmp_path: Path):
    file = tmp_path / "forged.zip"
    file.write_bytes(b"fake")
    with pytest.raises(ValueError, match="size / sha256"):
        run(file)


def test_ci_stage2_uses_only_pinned_unsw_and_never_promotes_model():
    path = (Path(__file__).resolve().parents[1] /
            ".github/workflows/source-only-feature-audit.yml")
    workflow = path.read_text(encoding="utf-8")
    assert "networkpulse.evaluation.source_only_candidates" in workflow
    assert "OneDrive_1_9-14-2026.zip" not in workflow
    assert "ton-source.zip" not in workflow
    assert "source-only-candidates.json" in workflow
