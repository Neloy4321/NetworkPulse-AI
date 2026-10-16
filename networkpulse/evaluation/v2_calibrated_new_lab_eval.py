"""Pre-registered, untouched-at-scoring *same-laboratory* V2 transfer test.

This is NOT independent-operated-site nor field deployed model acceptance.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import sklearn

from networkpulse.evaluation.unsw_to_toniot import digest
from networkpulse.evaluation.v2_predeclared_lab_eval import parse_capture
from networkpulse.feature_contract_v2 import V2_FEATURE_CONTRACT, features_v2
from networkpulse.generalization_evidence import wilson_interval

FROZEN_MODEL_SHA256 = "cd239783fd4318c0c4e897f1d451c2d5af4b42132979c79a4e489df626f538a5"
CUTOFF = 0.20
CAPTURES = {
    "CTU-IoT-Malware-Capture-42-1":
        "2019-01-10-14-34-38-192.168.1.197-zeek-conn-log.labeled",
    "CTU-Honeypot-Capture-4-1":
        "2018-10-25-14-06-32-192.168.1.132-zeek-conn.log.labeled",
}
MIN_BENIGN = 200
MIN_ATTACK = 100
MAX_FPR_UPPER = .05
MIN_RECALL_LOWER = .80


def bin_metrics(labels, positive) -> dict:
    tp = int(np.sum((labels == 1) & positive))
    fp = int(np.sum((labels == 0) & positive))
    tn = int(np.sum((labels == 0) & ~positive))
    fn = int(np.sum((labels == 1) & ~positive))
    benign, attack = tn + fp, tp + fn
    if benign < MIN_BENIGN or attack < MIN_ATTACK:
        return {
            "status": "BLOCKED_INSUFFICIENT_NATURAL_CLASS_SUPPORT",
            "benign": benign, "attack": attack,
            "confusion": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
            "fpr_upper_95": None, "recall_lower_95": None,
            "numeric_research_pass": False,
        }
    fpr95 = wilson_interval(fp, benign)
    recall95 = wilson_interval(tp, attack)
    return {
        "status": "LAB_RESEARCH_NUMERICAL_EVALUATION_ONLY",
        "benign": benign, "attack": attack,
        "confusion": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "fpr": fp / benign,
        "recall": tp / attack,
        "fpr_upper_95": fpr95[1],
        "recall_lower_95": recall95[0],
        "numeric_research_pass": (
            fpr95[1] <= MAX_FPR_UPPER and recall95[0] >= MIN_RECALL_LOWER
        ),
    }


def evaluate(bundle_path: Path, manifest_path: Path, targets: dict[str, Path]) -> dict:
    if tuple(targets) != tuple(CAPTURES):
        raise ValueError("Both fixed, previously unscored laboratory targets required")
    if digest(bundle_path) != FROZEN_MODEL_SHA256:
        raise ValueError("Model bytes differ from preregistered calibrated SHA")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (manifest.get("artifact_sha256") != FROZEN_MODEL_SHA256
            or manifest.get("protocol", {}).get("feature_contract") != V2_FEATURE_CONTRACT
            or manifest.get("protocol", {}).get("threshold") != CUTOFF
            or manifest.get("production_signed") is not False
            or manifest.get("independent_test_performed") is not False):
        raise ValueError("Immutable source-calibrated manifest or protocol mismatch")
    # This bundle was rebuilt from trusted source bytes and SHA verified before
    # any labeled target log is opened. Do not load arbitrary joblib/pickles.
    model = joblib.load(bundle_path)
    if (model.get("scikit_learn_version") != sklearn.__version__
            or model.get("fixed_cutoff") != CUTOFF
            or model.get("protocol_sha256") != manifest.get("protocol_sha256")
            or model.get("feature_contract") != V2_FEATURE_CONTRACT):
        raise ValueError("Runtime feature contract/model differs from frozen source")
    details = []
    all_labels, all_scores = [], []
    for name, path in targets.items():
        if path.name != CAPTURES[name] or path.stat().st_size > 10_000_000:
            raise ValueError("Unexpected target identity or bytes")
        raw_sha = digest(path)  # Verify/record complete input before reading labels.
        flows, labels, counters = parse_capture(path)
        if any(e.label is not None for e in flows):
            raise ValueError("Target label appeared inside runtime inference input")
        x = model["vectorizer"].transform([features_v2(e) for e in flows])
        pred = model["estimator"].predict_proba(x)
        if pred.shape != (len(flows), 2) or not np.isfinite(pred).all():
            raise ValueError("Invalid research model probability output")
        scores = pred[:, 1]
        result = bin_metrics(labels, scores >= CUTOFF)
        details.append({
            "capture": name, "source_sha256": raw_sha,
            "row_count": len(flows),
            "flows_with_real_missing_numbers": counters["missing_numeric"],
            "class_support": {
                "benign": counters["benign"], "attack": counters["malicious"]
            },
            "metrics": result,
        })
        all_labels.append(labels)
        all_scores.append(scores)
    combined = bin_metrics(
        np.concatenate(all_labels),
        np.concatenate(all_scores) >= CUTOFF,
    )
    return {
        "status": "predeclared_exposed_after_scoring_laboratory_transfer",
        "schema_version": 1,
        "research_model_sha256": FROZEN_MODEL_SHA256,
        "cutoff": CUTOFF,
        "sources_predeclared_in_repo_before_scoring": True,
        "same_iot23_laboratory_family_as_source_training": True,
        "training_sources_used_for_model_selection": [
            "UNSW-NB15", "IoT-23v2-34-1"
        ],
        "target_labels_used_to_fit_tune_or_choose_threshold": False,
        "independent_operator_site_verified": False,
        "actual_active_signed_deployment_verified": False,
        "p0_operational_ml_acceptance": "NO_GO",
        "captures": details,
        "combined_descriptive_lab_quality": combined,
        "limitations": [
            "Combined benign/attack may be sourced from different devices; mixture FPR/recall is descriptive only.",
            "Same research lab operator, not independent field site.",
            "Model unsigned and not live in an authenticated production network.",
            "Flow Wilson bounds do not account for clustered device/site correlation.",
            "All model outcomes are now exposed research evidence, not future sealed test labels.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--trojan-42", type=Path, required=True)
    parser.add_argument("--benign-4", type=Path, required=True)
    parser.add_argument("--aggregate-output", type=Path, required=True)
    opts = parser.parse_args()
    if opts.aggregate_output.exists():
        parser.error("refusing to replace genuine source evidence")
    result = evaluate(opts.model, opts.manifest, {
        "CTU-IoT-Malware-Capture-42-1": opts.trojan_42,
        "CTU-Honeypot-Capture-4-1": opts.benign_4,
    })
    opts.aggregate_output.parent.mkdir(parents=True, exist_ok=True)
    with opts.aggregate_output.open("x", encoding="utf-8") as dest:
        json.dump(result, dest, sort_keys=True, indent=2, allow_nan=False)
        dest.write("\n")
    print(json.dumps({
        "status": result["status"],
        "combined": result["combined_descriptive_lab_quality"],
        "capture_summaries": [
            {"capture": c["capture"], "metrics": c["metrics"]}
            for c in result["captures"]
        ],
        "p0_operational_ml_acceptance": "NO_GO",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
