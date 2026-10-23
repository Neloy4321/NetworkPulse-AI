"""Source-domain FPR REPAIR using exposed IoT-SFC v7 development flows.

Train only FIRST 200k source rows (already exposed), choose candidate+cutoff
using a deterministic source hostpair/proto-disjoint dev split; inspect the
NEXT 250k rows only after selection. Compare against the original frozen
baseline on the IDENTICAL later rows. This is same-laboratory research, NOT
independent field ML acceptance. No target rows from later segment fit/tune.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import zipfile
from collections import Counter, defaultdict
from itertools import islice
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer

from networkpulse.evaluation.iot_sfc_frozen_score import (
    adapt_v7_conn, digest, _quality, CUTOFF as BASELINE_CUTOFF,
)
from networkpulse.evaluation.iot_sfc_preregistration import (
    MODEL_SHA, TARGET_SHA, TARGET_SIZE,
)
from networkpulse.evaluation.iot_sfc_v7_conn_adapter import (
    RowNotEligible, inspect_untrusted_producer_label, verify_exact_header,
)
from networkpulse.feature_contract_v2 import features_v2
from networkpulse.generalization_evidence import wilson_interval

FIT_END = 200_000
EVAL_END = 450_000
SEED = 1729
FPR_DEV_UPPER_CAP = 0.03
RECALL_DEV_LOWER_GOAL = 0.80
MIN_CAL_BENIGN = 200
MIN_CAL_ATTACK = 100
CUTOFFS = tuple(i / 20 for i in range(1, 20))
MODEL_OPTIONS = {
    "rf_regularized": {"kind": "rf", "n_estimators": 120,
                        "max_depth": 12, "min_samples_leaf": 15},
    "rf_deeper": {"kind": "rf", "n_estimators": 120,
                  "max_depth": 18, "min_samples_leaf": 5},
    "extra_trees": {"kind": "extra", "n_estimators": 120,
                    "max_depth": 14, "min_samples_leaf": 12},
}


def group_key(flow) -> str:
    return f"{flow.src_ip}|{flow.dst_ip}|{flow.proto}"


def is_dev(flow) -> bool:
    payload = f"{SEED}|{group_key(flow)}".encode("utf-8")
    hash_part = int.from_bytes(hashlib.sha256(payload).digest()[:8], "big")
    return hash_part < int(0.25 * (2**64))


def flow_id(flow):
    return (flow.uid, flow.timestamp, str(flow.src_ip),
            str(flow.dst_ip), flow.src_port, flow.dst_port, flow.proto)


def read_partition(reader, header, n: int, *, seen: set) -> tuple[list, np.ndarray, Counter]:
    flows = []
    labels = []
    diagnostics = Counter()
    for cells in islice(reader, n):
        diagnostics["raw_rows"] += 1
        if len(cells) != len(header):
            diagnostics["invalid_row_width"] += 1
            continue
        row = dict(zip(header, cells))
        if row.get("log_type") != "conn":
            diagnostics["nonconn_excluded"] += 1
            continue
        try:
            event = adapt_v7_conn(row)
        except RowNotEligible:
            diagnostics["invalid_flow"] += 1
            continue
        try:
            evidence = inspect_untrusted_producer_label(row)
        except RowNotEligible:
            diagnostics["invalid_producer_label"] += 1
            continue
        identity = flow_id(event)
        if identity in seen:
            diagnostics["duplicate_excluded"] += 1
            continue
        seen.add(identity)
        flows.append(event)
        labels.append(evidence.producer_class)
        diagnostics["eligible_0" if not evidence.producer_class else "eligible_1"] += 1
    if diagnostics["raw_rows"] != n:
        raise ValueError("Original archive has insufficient rows for preregistered segments")
    return flows, np.asarray(labels, dtype=np.int8), diagnostics


def source_split(flows: list, labels: np.ndarray):
    train_indices = [i for i, f in enumerate(flows) if not is_dev(f)]
    dev_indices = [i for i, f in enumerate(flows) if is_dev(f)]
    if (set(group_key(flows[i]) for i in train_indices)
            & set(group_key(flows[i]) for i in dev_indices)):
        raise ValueError("Hostpair/proto split leakage")
    counts = {
        "fit": [int(np.sum(labels[train_indices] == 0)),
                int(np.sum(labels[train_indices] == 1))],
        "dev": [int(np.sum(labels[dev_indices] == 0)),
                int(np.sum(labels[dev_indices] == 1))],
    }
    if min(counts["fit"]) < 200:
        raise ValueError("Source-fit has insufficient natural classes")
    return train_indices, dev_indices, counts


def make_model(option: dict):
    parameters = dict(
        n_estimators=option["n_estimators"],
        max_depth=option["max_depth"],
        min_samples_leaf=option["min_samples_leaf"],
        random_state=SEED,
        class_weight="balanced_subsample",
        n_jobs=2,
    )
    if option["kind"] == "rf":
        return RandomForestClassifier(**parameters)
    return ExtraTreesClassifier(**parameters)


def confusion(labels, positive) -> Counter:
    return Counter({
        "tn": int(np.sum((labels == 0) & (~positive))),
        "fp": int(np.sum((labels == 0) & positive)),
        "fn": int(np.sum((labels == 1) & (~positive))),
        "tp": int(np.sum((labels == 1) & positive)),
    })


def _limits(counts: Counter):
    n0, n1 = counts["tn"] + counts["fp"], counts["tp"] + counts["fn"]
    if n0 < 1 or n1 < 1:
        return None, None
    return wilson_interval(counts["fp"], n0)[1], wilson_interval(counts["tp"], n1)[0]


def select_candidate(models_and_probs: dict, labels: np.ndarray) -> dict:
    benign = int(np.sum(labels == 0))
    attack = int(np.sum(labels == 1))
    if benign < MIN_CAL_BENIGN or attack < MIN_CAL_ATTACK:
        return {"selected": None, "reason": "DEVELOPMENT_GROUP_SUPPORT_INSUFFICIENT",
                "benign": benign, "attack": attack, "candidates": []}
    observed = []
    passing_budget = []
    for name, (model, probs) in models_and_probs.items():
        for cutoff in CUTOFFS:
            counted = confusion(labels, probs >= cutoff)
            upper, lower = _limits(counted)
            record = {
                "candidate": name, "cutoff": cutoff, "dev_confusion": dict(counted),
                "dev_fpr_upper95": upper, "dev_recall_lower95": lower,
                "fpr_budget_met": upper is not None and upper <= FPR_DEV_UPPER_CAP,
                "recall_goal_met": lower is not None and lower >= RECALL_DEV_LOWER_GOAL,
            }
            observed.append(record)
            if record["fpr_budget_met"]:
                passing_budget.append(record)
    selected = (sorted(passing_budget, key=lambda o: (
        -o["dev_recall_lower95"], o["cutoff"], o["candidate"],
    ))[0] if passing_budget else None)
    return {
        "selected": selected,
        "reason": ("SOURCE_DEV_FPR_BUDGET_MET" if selected
                   else "NO_SOURCE_DEV_CANDIDATE_MEETS_FPR_BUDGET"),
        "benign": benign, "attack": attack,
        "candidates": observed,
    }


def run(archive: Path, baseline_path: Path, output: Path) -> dict:
    if archive.name != "iot_dataset_v7.zip" or archive.stat().st_size != TARGET_SIZE:
        raise ValueError("Target source size/name changed")
    if digest(archive) != TARGET_SHA or digest(baseline_path) != MODEL_SHA:
        raise ValueError("Original dataset/frozen baseline SHA mismatch")
    if output.exists():
        raise ValueError("Refusing to overwrite research evidence")
    with zipfile.ZipFile(archive, "r", allowZip64=True) as zf:
        entries = zf.infolist()
        if len(entries) != 1 or entries[0].filename != "iot_dataset_v7.csv":
            raise ValueError("Archive member identity mismatch")
        with zf.open(entries[0], "r") as raw:
            with io.TextIOWrapper(raw, encoding="utf-8-sig", newline="") as text:
                previous = csv.field_size_limit()
                csv.field_size_limit(131072)
                try:
                    reader = csv.reader(text, strict=True)
                    header = next(reader)
                    verify_exact_header(header)
                    observed = set()
                    development, development_y, train_stats = read_partition(
                        reader, header, FIT_END, seen=observed,
                    )
                    train_i, dev_i, support = source_split(development, development_y)
                    encoder = DictVectorizer(sparse=False)
                    X_fit = encoder.fit_transform(
                        [features_v2(development[i]) for i in train_i]
                    )
                    y_fit = development_y[train_i]
                    X_dev = encoder.transform(
                        [features_v2(development[i]) for i in dev_i]
                    )
                    candidates = {}
                    for name, option in MODEL_OPTIONS.items():
                        trained = make_model(option).fit(X_fit, y_fit)
                        predictions = trained.predict_proba(X_dev)[:, 1]
                        if not np.isfinite(predictions).all():
                            raise ValueError("Source-dev candidate has invalid probabilities")
                        candidates[name] = (trained, predictions)
                    dev_selection = select_candidate(candidates, development_y[dev_i])
                    # Never view later rows until source-only model/cutoff selection closed.
                    # If insufficient source-dev support, do not use later labels to
                    # repair model selection. Evaluate only a fixed default candidate
                    # for diagnostic comparison and explicitly mark it unqualified.
                    if dev_selection["selected"]:
                        candidate_name = dev_selection["selected"]["candidate"]
                        candidate_cutoff = dev_selection["selected"]["cutoff"]
                    else:
                        candidate_name = "rf_regularized"
                        candidate_cutoff = 0.5
                    chosen = candidates[candidate_name][0]
                    del candidates, X_fit, X_dev
                    baseline = joblib.load(baseline_path)
                    if (baseline["fixed_cutoff"] != BASELINE_CUTOFF
                            or baseline["feature_contract"] != "missingness_aware_flow_v2"):
                        raise ValueError("Frozen baseline runtime/threshold changed")
                    # Zero exact source identity overlap within the scanned
                    # development prefix and later comparison segment.
                    holdout, holdout_y, holdout_stats = read_partition(
                        reader, header, EVAL_END - FIT_END, seen=observed,
                    )
                    X_new = encoder.transform([features_v2(f) for f in holdout])
                    X_old = baseline["vectorizer"].transform(
                        [features_v2(f) for f in holdout]
                    )
                    new_probs = chosen.predict_proba(X_new)[:, 1]
                    old_probs = baseline["estimator"].predict_proba(X_old)[:, 1]
                    if not np.isfinite(new_probs).all() or not np.isfinite(old_probs).all():
                        raise ValueError("Nonfinite target probabilities")
                    new_counts = confusion(holdout_y, new_probs >= candidate_cutoff)
                    old_counts = confusion(holdout_y, old_probs >= BASELINE_CUTOFF)
                    day_counts = defaultdict(lambda: {"y0": 0, "y1": 0})
                    overlap = 0
                    fit_groups = {group_key(development[i]) for i in train_i}
                    for flow, label in zip(holdout, holdout_y):
                        if group_key(flow) in fit_groups:
                            overlap += 1
                        key = flow.timestamp.date().isoformat()
                        day_counts[key]["y1" if label else "y0"] += 1
                finally:
                    csv.field_size_limit(previous)
    old_quality, new_quality = _quality(old_counts), _quality(new_counts)
    changed_fpr = None
    if old_quality.get("fpr") is not None and new_quality.get("fpr") is not None:
        changed_fpr = old_quality["fpr"] - new_quality["fpr"]
    return {
        "schema_version": 1,
        "status": "SOURCE_DOMAIN_ADAPTATION_RESEARCH_ONLY_EVALUATED",
        "dataset_sha256": TARGET_SHA,
        "original_model_sha256": MODEL_SHA,
        "baseline_cutoff": BASELINE_CUTOFF,
        "new_candidate_cutoff": candidate_cutoff,
        "new_candidate_model": candidate_name,
        "hyperparameters_fixed_before_later_holdout": MODEL_OPTIONS,
        "fit_prefix_rows": FIT_END, "later_comparison_end_row": EVAL_END,
        "source_exposed_prefix_stats": dict(train_stats),
        "source_group_split_support": support,
        "source_dev_selection": dev_selection,
        "candidate_unqualified_dev": dev_selection["selected"] is None,
        "later_segment_source_stats": dict(holdout_stats),
        "later_segment_score_rows": int(len(holdout_y)),
        "later_segment_days": dict(sorted(day_counts.items())),
        "later_segment_hostpair_seen_during_source_fit": overlap,
        "later_segment_exact_flow_duplicates_excluded": holdout_stats["duplicate_excluded"],
        "baseline_on_identical_later_rows": old_quality,
        "candidate_on_identical_later_rows": new_quality,
        "absolute_fpr_improvement": changed_fpr,
        "selection_used_later_segment_labels": False,
        "trained_on_previously_exposed_source_prefix": True,
        "later_segment_newly_exposed_now": True,
        "producer_labels_independently_adjudicated": False,
        "target_same_public_laboratory_no_independent_site": True,
        "new_candidate_production_signed_or_approved": False,
        "research_acceptance": "NOT_ESTABLISHED_SAME_LAB_AND_UNREVIEWED_LABELS",
        "operational_ml_p0": "NO_GO",
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    opts = p.parse_args()
    result = run(opts.archive, opts.baseline, opts.report)
    opts.report.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(opts.report, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(result, out, indent=2, sort_keys=True, allow_nan=False)
        out.write("\n")
    print(json.dumps({
        "baseline": result["baseline_on_identical_later_rows"],
        "candidate": result["candidate_on_identical_later_rows"],
        "fpr_improvement": result["absolute_fpr_improvement"],
        "research_acceptance": result["research_acceptance"],
        "operational_ml_p0": "NO_GO",
    }))


if __name__ == "__main__":
    main()
