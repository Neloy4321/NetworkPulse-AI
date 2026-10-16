"""Source-only ML benchmark foundations: never certify a reused external holdout."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from networkpulse.evaluation.source_only_feature_audit import (
    SAMPLE_CAP,
    feature_contract_audit,
    run,
    source_only_baseline,
    source_only_chronological_split,
)
from networkpulse.schemas import FlowEvent


def flow(i: int, *, ts: int | None = None, label: str | None = None) -> FlowEvent:
    return FlowEvent(
        timestamp=datetime.fromtimestamp(1400000000 + (i if ts is None else ts), timezone.utc),
        source="canonical",
        src_ip="198.51.100.10",
        dst_ip="203.0.113.20",
        src_port=10000 + i % 30000,
        dst_port=443 if i % 2 == 0 else 55000,
        proto="tcp" if i % 2 == 0 else "udp",
        duration=0 if i % 11 == 0 else 0.25 + i % 30,
        orig_bytes=10 + 3 * i,
        resp_bytes=0 if i % 13 == 0 else 50 + 2 * i,
        orig_pkts=2 + i % 25,
        resp_pkts=0 if i % 13 == 0 else 3 + i % 20,
        conn_state="sf" if i % 2 == 0 else "s0",
        label=label or ("benign" if i % 2 == 0 else "anomaly"),
    )


def test_audit_reports_aggregate_features_not_addresses_or_raw_flows():
    result = feature_contract_audit([flow(0), flow(1), flow(2)])
    serialized = json.dumps(result)
    assert result["native_feature_count_numeric"] == 10
    assert result["zero_duration_flows"] == 1
    assert result["distinct_connection_state_count"] == 2
    assert result["high_destination_port_flows"] == 1
    assert "198.51.100." not in serialized
    assert "203.0.113." not in serialized
    assert "src_ip" not in serialized
    assert "dst_ip" not in serialized
    assert "cross-sensor semantic equivalence is NOT established" in serialized


def test_contract_audit_rejects_empty_sample():
    with pytest.raises(ValueError, match="at least one canonical event"):
        feature_contract_audit([])


def test_chronological_split_separates_equal_timestamp_groups_and_deduplicates():
    events = [flow(i) for i in range(2000)]
    events[1499] = flow(1499, ts=1500)
    events.append(events[1500])
    fit, dev, removed = source_only_chronological_split(events)
    assert len(fit) >= 1000 and len(dev) >= 400
    assert max(e.timestamp for e in fit) < min(e.timestamp for e in dev)
    assert removed >= 1
    assert not ({e.key() for e in fit} & {e.key() for e in dev})


def test_chronological_split_rejects_time_group_collapse():
    events = [flow(i, ts=1) for i in range(2000)]
    with pytest.raises(ValueError, match="timestamp groups"):
        source_only_chronological_split(events)


def test_chronological_split_refuses_noncanonical_or_missing_labels():
    wrong = flow(1).model_copy(update={"source": "simulator"})
    with pytest.raises(ValueError, match="authentic labeled canonical"):
        source_only_chronological_split([wrong])
    unlabeled = flow(1).model_copy(update={"label": None})
    with pytest.raises(ValueError, match="authentic labeled canonical"):
        source_only_chronological_split([unlabeled])


def test_baseline_never_calls_research_gate_an_operational_acceptance():
    result = source_only_baseline([flow(i) for i in range(2200)])
    assert result["status"] == "source_only_development_measurement_not_acceptance"
    assert result["strict_timestamp_separation"] is True
    assert result["test_labels_used_to_fit"] is False
    assert result["model_feature_version"] == 1
    assert result["model_quantile"] == 0.995
    assert result["metrics"]["benign"] >= 100
    assert result["metrics"]["attack"] >= 100
    assert "operational_gate" not in result["metrics"]
    assert "production sign-off" in result["interpretation"]


def test_run_rejects_unpinned_source_bytes(tmp_path: Path):
    invalid = tmp_path / "forged.zip"
    invalid.write_bytes(b"not an approved archive")
    with pytest.raises(ValueError, match="non-pinned UNSW"):
        run(invalid, cap=SAMPLE_CAP)
    with pytest.raises(ValueError, match="sample cap is fixed"):
        run(invalid, cap=1000)


def test_workflow_never_uses_ton_for_source_only_selection():
    workflow = (Path(__file__).resolve().parents[1] /
                ".github/workflows/source-only-feature-audit.yml").read_text(encoding="utf-8")
    assert "source_only_feature_audit" in workflow
    assert "OneDrive_1_9-14-2026.zip" not in workflow
    assert "ton-source.zip" not in workflow
    assert "Fail when source-only audit is unavailable" in workflow
