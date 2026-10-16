"""Stage 3 research cross-capture stress safety and fail-closed metric tests."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pytest

from networkpulse.evaluation.source_only_capture_stress import (
    CAPTURE_CAP, CAPTURE_MEMBERS, fit_source_model, run, score_capture,
)
from networkpulse.evaluation.source_only_candidates import CANDIDATES
from networkpulse.evaluation.source_only_feature_audit import source_only_grouped_split
from networkpulse.schemas import FlowEvent


def flow(i: int, *, label: str | None = None) -> FlowEvent:
    return FlowEvent(
        timestamp=datetime.fromtimestamp(1450000000 + i, timezone.utc),
        source="canonical",
        src_ip=f"198.51.100.{i % 200 + 1}",
        dst_ip=f"203.0.113.{i // 200 + 1}",
        src_port=10000 + i % 20000,
        dst_port=443 if i % 3 == 0 else 50000,
        proto="tcp" if i % 2 == 0 else "udp",
        duration=float(1 + i % 60),
        orig_bytes=200 + i * 2,
        resp_bytes=80 + i,
        orig_pkts=2 + i % 40,
        resp_pkts=4 + i % 30,
        conn_state="sf" if i % 2 else "s0",
        label=label or ("anomaly" if i % 2 else "benign"),
    )


def source_and_new_capture():
    events = [flow(i) for i in range(2400)]
    fit, dev, _, _ = source_only_grouped_split(events)
    # Separate generated synthetic fixtures for unit tests; these are NEVER
    # presented as authentic network ML evidence.
    capture = [
        flow(i + 8000).model_copy(update={"label": "anomaly" if i % 2 else "benign"})
        for i in range(600)
    ]
    return fit, dev, capture


@pytest.mark.parametrize("candidate", CANDIDATES)
def test_cross_capture_score_preserves_fit_model_and_genuine_class_support(candidate):
    fit, _, capture = source_and_new_capture()
    bundle = fit_source_model(fit, candidate)
    digest_before = hashlib.sha256(
        np.asarray(bundle[1].feature_importances_).tobytes()
    ).hexdigest()
    result = score_capture(
        bundle, candidate, capture,
        fit_fingerprints=frozenset(),
        fit_ids=frozenset(e.key() for e in fit),
    )
    assert result["status"] == "measured_same_source_cross_capture_not_acceptance"
    assert result["training_or_threshold_changed_after_capture_labels"] is False
    assert result["research_numeric_thresholds_met"] in (True, False)
    assert result["class_counts"] == {"benign": 300, "anomaly": 300}
    assert "operational_gate" not in result["metrics"]
    assert sum(result["metrics"]["confusion_matrix"].values()) == 600
    digest_after = hashlib.sha256(
        np.asarray(bundle[1].feature_importances_).tobytes()
    ).hexdigest()
    assert digest_before == digest_after
    assert "198.51.100." not in json.dumps(result)


def test_cross_capture_removes_training_duplicates_without_changing_labels():
    fit, _, capture = source_and_new_capture()
    bundle = fit_source_model(fit, CANDIDATES[0])
    result = score_capture(
        bundle, CANDIDATES[0], capture + fit[:10],
        fit_fingerprints=frozenset(),
        fit_ids=frozenset(e.key() for e in fit),
    )
    assert result["overlapping_or_duplicate_events_excluded"] == 10
    assert result["rows_after_exact_overlap_exclusion"] == 600


def test_one_class_capture_is_reported_blocked_not_false_success():
    fit, _, capture = source_and_new_capture()
    bundle = fit_source_model(fit, CANDIDATES[0])
    all_benign = [e.model_copy(update={"label": "benign"}) for e in capture]
    result = score_capture(
        bundle, CANDIDATES[0], all_benign,
        fit_fingerprints=frozenset(), fit_ids=frozenset(),
    )
    assert result["status"] == "blocked_insufficient_capture_class_support"
    assert result["metrics"] is None
    assert result["class_counts"]["anomaly"] == 0
    assert "research_numeric_thresholds_met" not in result


def test_cross_capture_requires_approved_archive(tmp_path: Path):
    path = tmp_path / "unverified.zip"
    path.write_bytes(b"wrong archive")
    with pytest.raises(ValueError, match="unexpected bytes or SHA256"):
        run(path)


def test_capture_protocol_is_fixed_to_predeclared_unsw_only():
    assert CAPTURE_MEMBERS == (
        "UNSW-NB15_2.csv", "UNSW-NB15_3.csv", "UNSW-NB15_4.csv"
    )
    assert CAPTURE_CAP == 8000
    workflow = (Path(__file__).resolve().parents[1] /
                ".github/workflows/source-only-feature-audit.yml").read_text(
                    encoding="utf-8"
                )
    assert "networkpulse.evaluation.source_only_capture_stress" in workflow
    assert "source-only-capture-stress.json" in workflow
    assert "ton-source.zip" not in workflow
