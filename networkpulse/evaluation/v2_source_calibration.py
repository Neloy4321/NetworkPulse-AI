"""Predeclared source-only calibration for V2 supervised model (research only).

Uses SHA-approved *already exposed* UNSW + IoT 34-1 development families.
One deterministic host-pair/protocol-disjoint FIT/CAL split. The FIXED grid
only considers calibration metrics, NEVER Hakai 8-1, Torii 20-1, TON/CIC or
new true independent site labels. No guarantee of acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer

from networkpulse.evaluation.v2_mixed_source_freeze import (
    ESTIMATOR, IOT_SHA, UNSW_SHA, load_real_iot23, load_real_unsw,
)
from networkpulse.feature_contract_v2 import V2_FEATURE_CONTRACT, FlowV2, features_v2
from networkpulse.reliability import wilson_upper_bound

GROUP_SEED = 1729
CALIBRATION_FRACTION = 0.25
THRESHOLD_GRID = tuple(round(x * 0.025, 3) for x in range(2, 39))
# Dev calibration must provide an FPR safety margin below final acceptance.
SOURCE_CAL_FPR_UPPER_MAX = 0.025
MIN_CAL_BENIGN = 500
MIN_CAL_ATTACK = 200
MIN_FIT_PER_CLASS = 200
RECALL_LOWER_GOAL = 0.80
MODEL_HYPERPARAMETERS = dict(ESTIMATOR)


def is_calibration(flow: FlowV2) -> bool:
    # Only row identity is used to GROUP the split, never to model a prediction.
    text = (f"{GROUP_SEED}|{flow.src_ip}|{flow.dst_ip}|{flow.proto}").encode()
    digest = hashlib.sha256(text).digest()
    return int.from_bytes(digest[:8], "big") < int((2**64) * CALIBRATION_FRACTION)


def source_split(rows: list[FlowV2]):
    if not rows:
        raise ValueError("source split has no authentic labeled input")
    if any(e.label not in ("benign", "anomaly") for e in rows):
        raise ValueError("unlabeled flow in supervised source development")
    train = [e for e in rows if not is_calibration(e)]
    calibration = [e for e in rows if is_calibration(e)]
    def by_group(e):
        return (str(e.src_ip), str(e.dst_ip), e.proto)
    # Ensure ALL host/protocol groups, not just rows, are disjoint.
    if {by_group(e) for e in train} & {by_group(e) for e in calibration}:
        raise ValueError("source development group leakage")
    counts_train = Counter(e.label for e in train)
    counts_cal = Counter(e.label for e in calibration)
    if (min(counts_train.values(), default=0) < MIN_FIT_PER_CLASS
            or counts_train["benign"] < MIN_FIT_PER_CLASS
            or counts_train["anomaly"] < MIN_FIT_PER_CLASS
            or counts_cal["benign"] < MIN_CAL_BENIGN
            or counts_cal["anomaly"] < MIN_CAL_ATTACK):
        raise ValueError("source split has insufficient natural class support")
    return train, calibration


def recall_lower_bound(tp: int, attacks: int) -> float:
    if not 0 <= tp <= attacks or attacks < 1:
        raise ValueError("invalid attack recall count")
    return 1.0 - wilson_upper_bound(attacks - tp, attacks)


def select_dev_cutoff(calibration_labels, probabilities):
    labels = np.asarray(calibration_labels, dtype=np.int8)
    probs = np.asarray(probabilities, dtype=float)
    if labels.shape != probs.shape or labels.ndim != 1:
        raise ValueError("probability and label dimensions differ")
    if not np.isin(labels, (0, 1)).all() or not np.isfinite(probs).all():
        raise ValueError("invalid natural source labels or model scores")
    benign = int(np.sum(labels == 0))
    attacks = int(np.sum(labels == 1))
    if benign < MIN_CAL_BENIGN or attacks < MIN_CAL_ATTACK:
        raise ValueError("insufficient independent source calibration class support")
    checked = []
    admissible = []
    for cutoff in THRESHOLD_GRID:
        predicted = probs >= cutoff
        fp = int(np.sum(predicted & (labels == 0)))
        tp = int(np.sum(predicted & (labels == 1)))
        upper = wilson_upper_bound(fp, benign)
        lower = recall_lower_bound(tp, attacks)
        allowed = upper <= SOURCE_CAL_FPR_UPPER_MAX
        entry = {
            "threshold": cutoff, "false_positives": fp,
            "true_positives": tp, "benign": benign,
            "attacks": attacks,
            "source_cal_fpr_upper95": upper,
            "source_cal_recall_lower95": lower,
            "internal_fpr_safety_margin_satisfied": allowed,
        }
        checked.append(entry)
        if allowed:
            admissible.append(entry)
    # Lowest threshold retains most attacks while satisfying FPR safety cap.
    # If no candidate is valid, refuse promotion rather than adjusting cap.
    selected = admissible[0] if admissible else None
    return {
        "status": ("source_calibration_cutoff_selected"
                   if selected is not None else "blocked_source_calibration_fpr_budget"),
        "source_dev_only": True,
        "untouched_holdout_scored": False,
        "predeclared_grid": list(THRESHOLD_GRID),
        "source_fpr_upper_budget": SOURCE_CAL_FPR_UPPER_MAX,
        "source_recall_lower_goal": RECALL_LOWER_GOAL,
        "cutoff": selected["threshold"] if selected else None,
        "source_cal_recall_lower_goal_met": (
            selected["source_cal_recall_lower95"] >= RECALL_LOWER_GOAL
            if selected else False
        ),
        "source_cal_confusion": selected,
        "calibration_options": checked,
    }


def protocol() -> dict:
    return {
        "feature_contract": V2_FEATURE_CONTRACT,
        "unsw_original_zip_sha256": UNSW_SHA,
        "iot23_exposed_source_sha256": IOT_SHA,
        "supervised_model": "RandomForestClassifier",
        "estimator": dict(MODEL_HYPERPARAMETERS),
        "source_host_pair_protocol_group_seed": GROUP_SEED,
        "source_calibration_fraction": CALIBRATION_FRACTION,
        "threshold_grid": list(THRESHOLD_GRID),
        "source_cal_fpr_upper95_max": SOURCE_CAL_FPR_UPPER_MAX,
        "source_cal_recall_lower95_goal": RECALL_LOWER_GOAL,
        "never_use_hakai_torii_ton_cic_labels_for_cutoff": True,
    }


def train_and_calibrate(unsw_zip: Path, iot_path: Path):
    unsw = load_real_unsw(unsw_zip)
    iot = load_real_iot23(iot_path)
    data = unsw + iot
    fit_rows, cal_rows = source_split(data)
    vectorizer = DictVectorizer(sparse=False)
    x_fit = vectorizer.fit_transform([features_v2(e) for e in fit_rows])
    y_fit = np.array([int(e.label == "anomaly") for e in fit_rows])
    x_cal = vectorizer.transform([features_v2(e) for e in cal_rows])
    y_cal = np.array([int(e.label == "anomaly") for e in cal_rows])
    model = RandomForestClassifier(**MODEL_HYPERPARAMETERS).fit(x_fit, y_fit)
    if tuple(model.classes_) != (0, 1):
        raise ValueError("fit only contained one natural class")
    selected = select_dev_cutoff(y_cal, model.predict_proba(x_cal)[:, 1])
    report = {
        "schema_version": 1,
        "status": selected["status"],
        "protocol": protocol(),
        "model_frozen_from_exposed_training_only": True,
        "source_training_rows": len(fit_rows),
        "source_calibration_rows": len(cal_rows),
        "training_class_counts": dict(Counter(e.label for e in fit_rows)),
        "calibration_class_counts": dict(Counter(e.label for e in cal_rows)),
        "selected": selected,
        "operational_ml_acceptance": "NO_GO",
        "independent_operator_site_verified": False,
        "production_model_signed_and_deployed": False,
        "disclaimer": (
            "Internal source calibration after source exposure; "
            "never an independent-site validation or production quality PASS"
        ),
    }
    return model, vectorizer, report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--unsw-zip", type=Path, required=True)
    p.add_argument("--iot23-source", type=Path, required=True)
    p.add_argument("--research-model", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    args = p.parse_args()
    if args.research_model.exists() or args.report.exists():
        p.error("Cannot overwrite source calibration evidence")
    model, vectorizer, report = train_and_calibrate(args.unsw_zip, args.iot23_source)
    selected = report["selected"]
    if selected["cutoff"] is not None:
        proto = protocol()
        proto["threshold"] = selected["cutoff"]
        protocol_sha = hashlib.sha256(
            json.dumps(proto, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        bundle = {
            "schema_version": 2,
            "research_only": True,
            "production_approved": False,
            "feature_contract": V2_FEATURE_CONTRACT,
            "protocol_sha256": protocol_sha,
            "scikit_learn_version": sklearn.__version__,
            "fixed_cutoff": selected["cutoff"],
            "vectorizer": vectorizer,
            "estimator": model,
        }
        args.research_model.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(args.research_model, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out:
            joblib.dump(bundle, out, compress=3)
        report["research_model_sha256"] = hashlib.sha256(
            args.research_model.read_bytes()
        ).hexdigest()
        report["bundle_protocol_sha256"] = protocol_sha
        report["protocol"] = proto
        report["protocol_sha256"] = protocol_sha
        report["artifact_sha256"] = report["research_model_sha256"]
        report["production_signed"] = False
        report["independent_test_performed"] = False
        report["runtime_version"] = platform.python_version()
    else:
        report["research_model_sha256"] = None
        report["bundle_protocol_sha256"] = None
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")
    print(json.dumps({
        "status": report["status"],
        "chosen_cutoff": selected["cutoff"],
        "source_recall_lower_target_met": selected["source_cal_recall_lower_goal_met"],
        "fpr_safety_cap": SOURCE_CAL_FPR_UPPER_MAX,
        "operational_ml_acceptance": "NO_GO",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
