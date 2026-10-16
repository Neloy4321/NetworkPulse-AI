"""Fail-closed research readiness report, never operational ML certification.

This stage can only produce NO_GO. It evaluates supported source-only, previously
inspected UNSW captures with confidence intervals and predeclared thresholds.
External operator provenance, a signed deployed artifact and untouched physical
site validation are required before any operational acceptance assertion.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from networkpulse.evaluation.source_only_candidates import CANDIDATES
from networkpulse.evaluation.source_only_capture_stress import CAPTURE_MEMBERS

MAX_FPR_UPPER = 0.05
MIN_RECALL_LOWER = 0.8


def _finite_bound(value, *, low=0, high=1):
    return type(value) in (int, float) and low <= value <= high


def assess_readiness(stage1: dict, stage2: dict, stress: dict) -> dict:
    """Provenance- and score-check three research reports; never auto-promote."""
    if stage1.get("status") != "source_only_feature_audit_completed":
        raise ValueError("stage1 authentic source audit missing")
    if stage2.get("status") != "source_only_supervised_candidates_research_completed":
        raise ValueError("stage2 authentic source candidate evidence missing")
    if stress.get("status") != "same_source_cross_capture_stress_completed":
        raise ValueError("stage3 authentic same-source capture evidence missing")
    if stage2.get("production_model_changed") is not False:
        raise ValueError("stage2 altered production model or provenance")
    if stage2.get("auto_selected_winner") is not False:
        raise ValueError("research candidate auto-selection is prohibited")
    if stress.get("independent_site_verified") is not False:
        raise ValueError("same-source capture cannot claim independent physical site")
    if stress.get("production_model_changed") is not False:
        raise ValueError("stage3 production model mutation claim")
    source = stage1.get("protocol", {}).get("source_zip_sha256")
    if not isinstance(source, str) or len(source) != 64:
        raise ValueError("missing SHA-pinned source provenance")
    if source != stage2.get("protocol", {}).get("source_sha256"):
        raise ValueError("source provenance changed across Stage 1 / 2")
    if source != stress.get("protocol", {}).get("source_sha256"):
        raise ValueError("source provenance changed across Stage 1 / 3")
    if stage2.get("ton_or_external_target_used") is not False:
        raise ValueError("target-dependent research candidate evidence")
    if len(stage2.get("candidates", [])) != len(CANDIDATES):
        raise ValueError("stage2 candidate registry incomplete")
    if [item.get("candidate") for item in stage2["candidates"]] != list(CANDIDATES):
        raise ValueError("stage2 candidate identity changed")
    captures = stress.get("captures", [])
    if [item.get("member") for item in captures] != list(CAPTURE_MEMBERS):
        raise ValueError("missing or additional stage3 source capture")

    results = {}
    for candidate in CANDIDATES:
        by_capture = []
        for capture in captures:
            record = capture.get("measured_from_source_capture_1_fit", {}).get(candidate)
            if not isinstance(record, dict):
                raise ValueError("predeclared candidate absent from stress capture")
            status = record.get("status")
            if status == "blocked_insufficient_capture_class_support":
                by_capture.append({
                    "capture": capture["member"],
                    "status": "blocked_insufficient_support",
                    "numeric_thresholds_met": False,
                })
                continue
            if status != "measured_same_source_cross_capture_not_acceptance":
                raise ValueError("invalid or fabricated candidate measurement status")
            measured = record.get("metrics")
            counts = record.get("class_counts", {})
            if not isinstance(measured, dict):
                raise ValueError("missing research score evidence")
            matrix = measured.get("confusion_matrix", {})
            if (set(matrix) != {"tp", "fp", "tn", "fn"} or
                    any(type(matrix[k]) is not int or matrix[k] < 0 for k in matrix)):
                raise ValueError("malformed confusion matrix in stress evidence")
            benign, attack = matrix["fp"] + matrix["tn"], matrix["tp"] + matrix["fn"]
            if benign < 100 or attack < 100:
                raise ValueError("insufficient research flow class support")
            if counts != {"benign": benign, "anomaly": attack}:
                raise ValueError("stress reported counts do not match confusion matrix")
            fpr_ci = measured.get("fpr_wilson95")
            recall_ci = measured.get("recall_wilson95")
            if (not isinstance(fpr_ci, list) or len(fpr_ci) != 2 or
                    not isinstance(recall_ci, list) or len(recall_ci) != 2 or
                    not all(_finite_bound(v) for v in fpr_ci + recall_ci) or
                    fpr_ci[0] > fpr_ci[1] or recall_ci[0] > recall_ci[1]):
                raise ValueError("unsupported or malformed Wilson intervals")
            met = fpr_ci[1] <= MAX_FPR_UPPER and recall_ci[0] >= MIN_RECALL_LOWER
            if record.get("research_numeric_thresholds_met") is not met:
                raise ValueError("untrustworthy research quality-flag report")
            by_capture.append({
                "capture": capture["member"],
                "status": "measured",
                "benign": benign,
                "attack": attack,
                "false_positives": matrix["fp"],
                "missed_attacks": matrix["fn"],
                "fpr_wilson95_upper": fpr_ci[1],
                "recall_wilson95_lower": recall_ci[0],
                "numeric_thresholds_met": met,
            })
        results[candidate] = {
            "same_source_capture_numeric_gate_met_all": all(
                record["numeric_thresholds_met"] for record in by_capture
            ),
            "captured": by_capture,
        }

    return {
        "schema_version": 1,
        "status": "research_no_go_independent_operational_ml_unverified",
        "decision": "NO_GO",
        "all_candidates_still_research_only": True,
        "production_artifact_approved": False,
        "model_freeze_authorized": False,
        "operational_acceptance_demonstrated": False,
        "new_external_independent_capture_evaluated": False,
        "reason": (
            "No operational certification may rely on correlated same-UNSW "
            "capture research; cross-capture numerical gates must be documented "
            "and independently verified deployment evidence is absent."
        ),
        "source_sha256": source,
        "quality_thresholds": {
            "max_benign_fpr_95_upper": MAX_FPR_UPPER,
            "min_attack_recall_95_lower": MIN_RECALL_LOWER,
        },
        "research_candidates": results,
        "blocking_actions": [
            "Resolve cross-capture false alarm generalization without tuning exposed targets.",
            "Document sensor-to-native flow feature parity and source temporal/host leakage controls.",
            "Pre-register candidate-selection protocol and freeze reviewed model artifact plus training ledger.",
            "Obtain a newly acquired untouched independently operated, legitimately labeled external capture.",
            "Verify frozen/signed model equivalence to actual deployed service, alert rates, SLOs and field behavior.",
            "Rotate earlier-exposed R2 credentials and provision a bucket-scoped read-only CI token.",
        ],
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stage1", type=Path, required=True)
    p.add_argument("--stage2", type=Path, required=True)
    p.add_argument("--stress", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        p.error("refusing overwrite of existing readiness artifact")
    for value in (args.stage1, args.stage2, args.stress):
        if not value.is_file():
            p.error("required research report absent")
    report = assess_readiness(*(
        json.loads(path.read_text(encoding="utf-8"))
        for path in (args.stage1, args.stage2, args.stress)
    ))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    print(json.dumps({
        "decision": report["decision"],
        "source_sha256": report["source_sha256"],
        "candidate_gates": {
            name: obj["same_source_capture_numeric_gate_met_all"]
            for name, obj in report["research_candidates"].items()
        },
        "production_artifact_approved": report["production_artifact_approved"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
