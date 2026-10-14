"""Predeclared benign-calibration policies on an unseen UNSW raw capture.

Earlier source capture: UNSW-NB15_1.csv. Reserved evaluation capture:
UNSW-NB15_3.csv. No test labels used to fit, choose quantile or calibrate.
The comparison is exploratory once results are observed; do not cherry-pick a
winner without a new independent network/site holdout.
"""
from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path

from networkpulse.detector import train
from networkpulse.evaluation.live_unsw import evaluate_scores, read_reservoir


POLICIES = (0.97, 0.99, 0.995)
TRAIN_FILE = "UNSW-NB15_1.csv"
TEST_FILE = "UNSW-NB15_3.csv"


def _event_identity_unique(events, forbidden=None):
    blocked = set(forbidden or ())
    kept = []
    for item in events:
        key = item.key()
        if key not in blocked:
            blocked.add(key)
            kept.append(item)
    return kept


def compare_calibration_policies(archive: Path, *, seed: int = 42,
                                 train_cap: int = 2200,
                                 test_cap: int = 1300) -> dict:
    """Uniform sampling is per selected capture, not attack-label stratified."""
    if train_cap < 1000 or test_cap < 500:
        raise ValueError("evaluation sample caps too small")
    with zipfile.ZipFile(archive) as z:
        train_sample, train_scan = read_reservoir(z, TRAIN_FILE, train_cap, seed)
        test_sample, test_scan = read_reservoir(z, TEST_FILE, test_cap, seed + 1)
    training = _event_identity_unique(train_sample)
    train_keys = {x.key() for x in training}
    holdout = _event_identity_unique(test_sample, train_keys)
    if len(training) < 400 or len(holdout) < 100:
        raise ValueError("insufficient nonduplicated capture samples")
    if max(x.timestamp for x in training) >= min(x.timestamp for x in holdout):
        raise ValueError("capture overlap invalidates time separation")
    if {e.label for e in holdout} != {"anomaly", "benign"}:
        raise ValueError("unseen capture must contain both benign and attack rows")
    # Train() itself applies chronological 60/15/25 split to earlier capture;
    # all calibration outcomes come solely from those earlier BENIGN rows.
    policies = {}
    for q in POLICIES:
        candidate = train(training, seed=seed, quantile=q,
                          source="unsw_raw_calibration_policy_study")
        metrics = evaluate_scores(holdout, candidate.score(holdout))
        policies[str(q)] = {
            "calibration_quantile": q,
            "threshold": float(candidate.threshold),
            "calibration_count": candidate.metadata["cal_count"],
            "fit_count": candidate.metadata["train_count"],
            "holdout_capture_metrics": metrics,
            "calibration_only_diagnostics": candidate.metadata["calibration_diagnostics"],
        }
    return {
        "status": "exploratory_comparison_not_model_selection",
        "dataset": "UNSW-NB15 original 49-column raw CSV",
        "train": train_scan, "test": test_scan,
        "sample_counts": {"train_unique": len(training), "test_unique": len(holdout),
                          "test_benign": sum(x.label == "benign" for x in holdout),
                          "test_attacks": sum(x.label == "anomaly" for x in holdout)},
        "time_split_verified_from_sample": True,
        "independent_network_site_verified": False,
        "quantiles_predeclared_before_test_run": list(POLICIES),
        "policies": policies,
        "limitations": [
            "Quantile comparison reports all fixed policies; no best model is chosen on test.",
            "Benign quantile does not guarantee future FPR under time/domain shift.",
            "Capture three is a later held-out file, but shares original cyber range context.",
            "Selected samples are bounded reservoirs with class proportions not deployment rates.",
            "No artifact is promoted, saved or deployed.",
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-train", type=int, default=2200)
    parser.add_argument("--max-test", type=int, default=1300)
    args = parser.parse_args()
    result = compare_calibration_policies(args.zip, train_cap=args.max_train,
                                          test_cap=args.max_test)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "sample_counts": result["sample_counts"],
                      "policies": {q: v["holdout_capture_metrics"]
                                   for q, v in result["policies"].items()}}, indent=2))


if __name__ == "__main__":
    main()
