"""Verify archived P0 numerical evidence and prevent false operational promotion.

Recalculate all metrics from confusion cells, Wilson 95% CI and source pins.
This validator never loads unsigned pickles, source ZIP, target rows or secrets.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from networkpulse.generalization_evidence import wilson_interval

DEFAULT = Path(__file__).resolve().parents[2] / (
    "docs/P0_IOT_SFC_V7_VERIFIED_NUMERIC_GATE_20261023.json"
)

MODEL_SHA = "ecc320bc693481fc45b143b48ffbebcb117899e888e4687930f3361501af6fa1"
BASELINE_SHA = "cd239783fd4318c0c4e897f1d451c2d5af4b42132979c79a4e489df626f538a5"
DATA_SHA = "070b1356e5bd296e584109fae79139cfe0f20ff4790f69e42994d67362cb9f62"
SOURCE_RESULT_SHA = "4c80e0a068cd623edbf612daf38037544fd1f1908fba70392c4e6b525920dc49"
COUNTS = {"tn": 120141, "fp": 5085, "fn": 2547, "tp": 213986}
DAYS = {
    "2025-04-12": {"tn": 60433, "fp": 585, "fn": 0, "tp": 0},
    "2025-04-13": {"tn": 59707, "fp": 4500, "fn": 2547, "tp": 213986},
    "2025-04-14": {"tn": 1, "fp": 0, "fn": 0, "tp": 0},
}


def verify(report: dict) -> dict:
    """Strict evidence validation, including the caveats, not just two percentages."""
    if type(report) is not dict or report.get("schema_version") != 1:
        raise ValueError("Unsupported gate evidence schema")
    model, source, prov, gates = (
        report["model"], report["source"], report["provenance"], report["gates"]
    )
    if (model.get("artifact_sha256") != MODEL_SHA
            or model.get("baseline_rf_sha256") != BASELINE_SHA
            or type(model.get("fixed_cutoff")) not in (float, int)
            or model["fixed_cutoff"] != 0.9
            or model.get("baseline_rf_cutoff") != 0.2
            or model.get("feature_contract") != "missingness_aware_flow_v2"
            or model.get("research_only") is not True
            or model.get("production_approved") is not False
            or model.get("operator_signature_verified") is not False
            or source.get("archive_sha256") != DATA_SHA
            or source.get("producer_labels_human_adjudicated") is not False
            or source.get("same_public_lab_as_training") is not True
            or source.get("candidate_testing_data_used_for_selection") is not False
            or source.get("training_through") != "2025-04-08"
            or source.get("calibration_date") != "2025-04-10"
            or source.get("actual_scored_test_days") != list(DAYS)
            or source.get("training_dev_shared_hostpair_protocol_count") != 121320
            or prov.get("original_test_workflow_run") != 39921326610
            or prov.get("aggregate_result_artifact_id") != 12487502789
            or prov.get("aggregate_result_sha256") != SOURCE_RESULT_SHA):
        raise ValueError("Model/source/provenance identity mutated or unsupported")
    if gates != {
        "fpr_wilson_upper_95_max": 0.05,
        "recall_wilson_lower_95_min": 0.8,
        "min_benign": 200, "min_attack": 100,
        "min_distinct_capture_days": 3,
    }:
        raise ValueError("Frozen quality gates modified")
    results = report["results"]
    if results.get("confusion") != COUNTS:
        raise ValueError("Confusion counts tampered")
    tn, fp, fn, tp = (COUNTS[k] for k in ("tn", "fp", "fn", "tp"))
    benign, attack = tn + fp, fn + tp
    if (results.get("benign") != benign or results.get("attack") != attack
            or results.get("test_eligible_flows") != benign + attack):
        raise ValueError("Confusion denominator changed")
    fpr = fp / benign
    recall = tp / attack
    upper = wilson_interval(fp, benign)[1]
    lower = wilson_interval(tp, attack)[0]
    for key, computed in [
        ("fpr", fpr), ("fpr_wilson_upper_95", upper),
        ("recall", recall), ("recall_wilson_lower_95", lower),
    ]:
        if abs(results.get(key, -99) - computed) > 1e-12:
            raise ValueError("Metric mismatches confusion counts: " + key)
    days = results.get("per_day")
    if not isinstance(days, dict) or set(days) != set(DAYS):
        raise ValueError("Daily coverage misrepresented")
    recombined = {key: 0 for key in COUNTS}
    for day, day_counts in DAYS.items():
        actual = days[day]
        for field, expected in day_counts.items():
            if actual.get(field) != expected:
                raise ValueError("Daily confusion cell changed")
            recombined[field] += expected
        if (actual.get("benign") != day_counts["tn"] + day_counts["fp"]
                or actual.get("attack") != day_counts["fn"] + day_counts["tp"]):
            raise ValueError("Daily support inconsistent")
    if recombined != COUNTS:
        raise ValueError("Daily totals != aggregate")
    day13 = days["2025-04-13"]
    day_fpr_upper = wilson_interval(day13["fp"], day13["benign"])[1]
    if (abs(day13.get("fpr_upper95", -9) - day_fpr_upper) > 1e-12
            or day13.get("per_day_fpr_gate_pass") is not False
            or day_fpr_upper <= 0.05
            or results.get("per_day_robustness_gate_pass") is not False
            or results.get("distinct_days_with_both_classes") != 1
            or results.get("unseen_training_hostpair_attack_support") != 0
            or results.get("flow_wilson_bounds_ignore_day_and_site_clustering")
            is not True):
        raise ValueError("Per-day/domain-shift limitations hidden")
    supported = (
        benign >= gates["min_benign"] and attack >= gates["min_attack"]
        and len(days) >= gates["min_distinct_capture_days"]
    )
    pointwise_numeric_pass = (
        supported and upper <= gates["fpr_wilson_upper_95_max"]
        and lower >= gates["recall_wilson_lower_95_min"]
    )
    if (not pointwise_numeric_pass
            or results.get("aggregate_pointwise_numeric_gate_pass") is not True):
        raise ValueError("Reported numerical PASS is unsupported")
    decision = report["release_decision"]
    if decision != {
        "research_aggregate_numerical_criterion": "PASS",
        "research_multi_day_and_independent_label_qualification": "NOT_ESTABLISHED",
        "independent_field_site": "NOT_VERIFIED",
        "human_label_ground_truth": "NOT_VERIFIED",
        "signed_operator_model": "NOT_AVAILABLE",
        "active_https_oidc_with_live_sensor_parity": "NOT_VERIFIED",
        "production_p0": "NO_GO",
        "false_claims_forbidden": True,
    }:
        raise ValueError("Operational acceptance or signoff falsified")
    if report.get("status") != (
        "AGGREGATE_POINTWISE_NUMERIC_RESEARCH_PASS_NOT_OPERATIONAL_ACCEPTANCE"
    ):
        raise ValueError("Misleading research status")
    return {
        "aggregate_numeric_research": "PASS",
        "fpr": fpr, "fpr_upper_95": upper,
        "recall": recall, "recall_lower_95": lower,
        "day_2025_04_13_fpr_upper_95": day_fpr_upper,
        "multi_day_field_generalization": "NOT_ESTABLISHED",
        "operational_ml_p0": "NO_GO",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, default=DEFAULT)
    args = parser.parse_args()
    if args.evidence.is_symlink() or args.evidence.stat().st_size > 50_000:
        raise ValueError("Refuse symlink or oversized evidence")
    report = json.loads(args.evidence.read_text(encoding="utf-8"))
    print(json.dumps(verify(report), sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
