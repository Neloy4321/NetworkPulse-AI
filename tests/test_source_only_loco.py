"""No invented holdout: four-fold already-exposed UNSW development checks."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from networkpulse.evaluation.source_only_loco import (
    MEMBERS, MEMBER_SEEDS, SAMPLE_PER_MEMBER, evaluate_fold, run,
)
from networkpulse.evaluation.source_only_candidates import CANDIDATES
from networkpulse.schemas import FlowEvent


def flow(i, source_member):
    member_index = MEMBERS.index(source_member)
    value = member_index * 10000 + i
    return FlowEvent(
        timestamp=datetime.fromtimestamp(1450000000 + value, timezone.utc),
        source="canonical",
        src_ip=f"198.51.100.{value % 210 + 1}",
        dst_ip=f"203.0.113.{value // 210 % 210 + 1}",
        src_port=10000 + i % 30000,
        dst_port=443,
        proto="tcp",
        duration=float(1 + i % 10),
        orig_bytes=1000 + i,
        resp_bytes=800 + i,
        orig_pkts=2 + i % 50,
        resp_pkts=4 + i % 30,
        conn_state="sf",
        label="anomaly" if i % 2 else "benign",
    )


def data():
    return {m: [flow(i, m) for i in range(450)] for m in MEMBERS}


def test_predeclared_four_source_members_and_seed_are_fixed():
    assert MEMBERS == (
        "UNSW-NB15_1.csv", "UNSW-NB15_2.csv",
        "UNSW-NB15_3.csv", "UNSW-NB15_4.csv",
    )
    assert MEMBER_SEEDS == (60, 61, 62, 63)
    assert SAMPLE_PER_MEMBER == 6000


def test_loco_excludes_one_capture_and_does_not_report_site_acceptance():
    fold = evaluate_fold(data(), MEMBERS[0])
    assert fold["excluded_capture"] == MEMBERS[0]
    assert fold["fit_members"] == list(MEMBERS[1:])
    assert fold["physically_independent_site"] is False
    assert fold["time_independence_not_proven"] is True
    assert fold["dev_class_counts"] == {"benign": 225, "anomaly": 225}
    assert fold["fit_class_counts"] == {"benign": 675, "anomaly": 675}
    assert fold["status"] == "measured_exposed_source_capture_development_only"
    assert set(fold["models"]) == set(CANDIDATES)
    for result in fold["models"].values():
        assert result["training_or_threshold_changed_after_capture_labels"] is False
        assert result["overlapping_or_duplicate_events_excluded"] == 0
        assert "operational_gate" not in result["metrics"]
    assert "198.51.100." not in json.dumps(fold)


def test_unbalanced_capture_is_not_converted_into_fake_good_recall():
    sample = data()
    sample[MEMBERS[1]] = [
        flow(i, MEMBERS[1]).model_copy(update={"label": "benign"})
        for i in range(450)
    ]
    fold = evaluate_fold(sample, MEMBERS[1])
    assert fold["status"] == "blocked_insufficient_natural_class_support"
    assert fold["models"] == {}
    assert fold["dev_class_counts"]["anomaly"] == 0


def test_wrong_capture_identity_or_missing_member_fails_closed():
    sample = data()
    sample.pop(MEMBERS[-1])
    with pytest.raises(ValueError, match="predeclared"):
        evaluate_fold(sample, MEMBERS[0])
    with pytest.raises(ValueError, match="predeclared"):
        evaluate_fold(data(), "TON-synthetic-claim.csv")


def test_verified_source_zip_required(tmp_path: Path):
    f = tmp_path / "fake.zip"
    f.write_bytes(b"not unsw")
    with pytest.raises(ValueError, match="unapproved source archive"):
        run(f)


def test_workflow_never_loads_exposed_ton_into_source_loco():
    workflow = (Path(__file__).resolve().parents[1] /
                ".github/workflows/source-only-feature-audit.yml").read_text(
                    encoding="utf-8"
                )
    assert "networkpulse.evaluation.source_only_loco" in workflow
    assert "source-only-loco.json" in workflow
    assert "ton-source.zip" not in workflow
