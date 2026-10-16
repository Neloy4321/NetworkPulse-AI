"""Stage 3 source-only go/no-go report is never an independent certification."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from networkpulse.evaluation.source_only_readiness import assess_readiness
from networkpulse.evaluation.source_only_candidates import CANDIDATES
from networkpulse.evaluation.source_only_capture_stress import CAPTURE_MEMBERS


def reports(*, hit: bool = False):
    sha = "a" * 64
    stage1 = {
        "status": "source_only_feature_audit_completed",
        "protocol": {"source_zip_sha256": sha},
    }
    stage2 = {
        "status": "source_only_supervised_candidates_research_completed",
        "production_model_changed": False, "auto_selected_winner": False,
        "ton_or_external_target_used": False,
        "protocol": {"source_sha256": sha},
        "candidates": [{"candidate": x} for x in CANDIDATES],
    }
    stress = {
        "status": "same_source_cross_capture_stress_completed",
        "independent_site_verified": False,
        "production_model_changed": False,
        "protocol": {"source_sha256": sha},
        "captures": [],
    }
    for member in CAPTURE_MEMBERS:
        records = {}
        for candidate in CANDIDATES:
            cm = (
                {"tn": 990, "fp": 10, "fn": 2, "tp": 198} if hit
                else {"tn": 700, "fp": 300, "fn": 2, "tp": 198}
            )
            records[candidate] = {
                "status": "measured_same_source_cross_capture_not_acceptance",
                "class_counts": {"benign": 1000, "anomaly": 200},
                "metrics": {
                    "confusion_matrix": cm,
                    "fpr_wilson95": [0.004, 0.018] if hit else [0.27, 0.33],
                    "recall_wilson95": [0.95, 0.999],
                },
                "research_numeric_thresholds_met": hit,
            }
        stress["captures"].append({
            "member": member, "measured_from_source_capture_1_fit": records
        })
    return stage1, stage2, stress


def test_realistic_failed_source_gates_never_approve_production():
    report = assess_readiness(*reports())
    assert report["decision"] == "NO_GO"
    assert report["production_artifact_approved"] is False
    assert report["model_freeze_authorized"] is False
    assert report["operational_acceptance_demonstrated"] is False
    assert all(
        not x["same_source_capture_numeric_gate_met_all"]
        for x in report["research_candidates"].values()
    )
    assert "src_ip" not in json.dumps(report)


def test_perfect_source_capture_scores_cannot_certify_site():
    report = assess_readiness(*reports(hit=True))
    assert all(
        x["same_source_capture_numeric_gate_met_all"]
        for x in report["research_candidates"].values()
    )
    assert report["decision"] == "NO_GO"
    assert report["model_freeze_authorized"] is False
    assert report["new_external_independent_capture_evaluated"] is False


def test_untrustworthy_numeric_flag_is_rejected():
    a, b, c = reports()
    c["captures"][0]["measured_from_source_capture_1_fit"][CANDIDATES[0]][
        "research_numeric_thresholds_met"
    ] = True
    with pytest.raises(ValueError, match="untrustworthy"):
        assess_readiness(a, b, c)


def test_missing_source_provenance_or_wrong_model_sequence_fails():
    a, b, c = reports()
    b["protocol"]["source_sha256"] = "b" * 64
    with pytest.raises(ValueError, match="provenance changed"):
        assess_readiness(a, b, c)
    a, b, c = reports()
    b["candidates"].reverse()
    with pytest.raises(ValueError, match="candidate identity changed"):
        assess_readiness(a, b, c)


def test_blocked_one_class_capture_stays_blocked_in_report():
    a, b, c = reports()
    c["captures"][0]["measured_from_source_capture_1_fit"][CANDIDATES[0]] = {
        "status": "blocked_insufficient_capture_class_support"
    }
    report = assess_readiness(a, b, c)
    assert report["decision"] == "NO_GO"
    assert report["research_candidates"][CANDIDATES[0]]["captured"][0]["status"] == (
        "blocked_insufficient_support"
    )


def test_malformed_matrix_and_invalid_ci_cannot_be_reported_as_success():
    a, b, c = reports()
    entry = c["captures"][0]["measured_from_source_capture_1_fit"][CANDIDATES[0]]
    entry["metrics"]["confusion_matrix"]["fp"] = -1
    with pytest.raises(ValueError, match="malformed confusion"):
        assess_readiness(a, b, c)
    a, b, c = reports()
    entry = c["captures"][0]["measured_from_source_capture_1_fit"][CANDIDATES[0]]
    entry["metrics"]["fpr_wilson95"] = [0.3, float("nan")]
    with pytest.raises(ValueError, match="malformed Wilson"):
        assess_readiness(a, b, c)


def test_rejects_false_independent_site_claim():
    a, b, c = reports()
    c["independent_site_verified"] = True
    with pytest.raises(ValueError, match="same-source capture"):
        assess_readiness(a, b, c)


def test_readiness_requires_expected_three_pinned_reports():
    a, b, c = reports()
    c["captures"].pop()
    with pytest.raises(ValueError, match="missing or additional"):
        assess_readiness(a, b, c)


def test_workflow_checks_readiness_before_green(tmp_path: Path):
    workflow = (Path(__file__).resolve().parents[1] /
                ".github/workflows/source-only-feature-audit.yml").read_text(
                    encoding="utf-8"
                )
    assert "networkpulse.evaluation.source_only_readiness" in workflow
    assert "source-only-readiness.json" in workflow
    assert "operational_acceptance_demonstrated" in workflow


def test_report_is_pure_and_does_not_mutate_untrusted_inputs():
    inputs = reports()
    before = copy.deepcopy(inputs)
    assess_readiness(*inputs)
    assert inputs == before
