"""One-shot forward-day IoT-SFC v7 supervised FPR repair and descriptive future transfer.

April 3-8 FIT, April 10 DEV threshold selection, >=April 12 TEST.
Test labels are not inspected until source model / cutoff locked. No labels
or human/sensor identifiers ever enter feature vectors. This is SAME public
lab, NOT independent-site operational acceptance.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import zipfile
from collections import Counter, defaultdict
from datetime import date
from itertools import islice
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.feature_extraction import DictVectorizer

from networkpulse.evaluation.iot_sfc_domain_adapt_fpr import (
    EVAL_END, MODEL_OPTIONS, FPR_DEV_UPPER_CAP,
    CUTOFFS, make_model, _limits,
    flow_id, group_key, read_partition,
)
from networkpulse.evaluation.iot_sfc_frozen_score import (
    CUTOFF as BASELINE_CUTOFF, digest, _quality, adapt_v7_conn,
)
from networkpulse.evaluation.iot_sfc_preregistration import (
    MODEL_SHA, TARGET_SHA, TARGET_SIZE,
)
from networkpulse.evaluation.iot_sfc_v7_conn_adapter import (
    RowNotEligible, inspect_untrusted_producer_label, verify_exact_header,
)
from networkpulse.feature_contract_v2 import features_v2

TRAIN_MAX = date(2025, 4, 8)
CAL_DATE = date(2025, 4, 10)
TEST_MIN = date(2025, 4, 12)
TEST_MAX = date(2025, 4, 17)
TAIL_ROW_LIMIT = 7_000_000
TARGET_SCORED_ROWS = 120_000
MIN_DAYS = 3
BATCH = 2048
MIN_DEV_BENIGN = 200
MIN_DEV_ATTACK = 100
MIN_TEST_BENIGN = 200
MIN_TEST_ATTACK = 100
RESEARCH_FPR_UPPER = 0.05
RESEARCH_RECALL_LOWER = 0.80


def choose_on_exposed_apr10(train, train_y, dev, dev_y):
    train_support = Counter(int(x) for x in train_y)
    dev_support = Counter(int(x) for x in dev_y)
    if (min(train_support.values(), default=0) < 200
            or train_support[0] < 200 or train_support[1] < 200
            or dev_support[0] < MIN_DEV_BENIGN
            or dev_support[1] < MIN_DEV_ATTACK):
        raise ValueError("Chronological FIT/DEV class support insufficient")
    encoder = DictVectorizer(sparse=False)
    x_fit = encoder.fit_transform([features_v2(f) for f in train])
    x_dev = encoder.transform([features_v2(f) for f in dev])
    candidates = {}
    for name, option in MODEL_OPTIONS.items():
        estimator = make_model(option).fit(x_fit, train_y)
        probs = estimator.predict_proba(x_dev)[:, 1]
        if probs.shape != (len(dev_y),) or not np.isfinite(probs).all():
            raise ValueError("Malformed development probabilities")
        candidates[name] = (estimator, probs)
    eligible = []
    candidate_summaries = {}
    for name, (_estimator, scores) in candidates.items():
        for cutoff in CUTOFFS:
            cm = confusion(dev_y, scores >= cutoff)
            up, low = _limits(cm)
            if up is not None and low is not None and up <= FPR_DEV_UPPER_CAP:
                eligible.append({
                    "candidate": name, "cutoff": cutoff,
                    "dev_fpr_upper95": up, "dev_recall_lower95": low,
                    "dev_confusion": dict(cm),
                })
        candidate_summaries[name] = {
            "threshold_grid_evaluated": len(CUTOFFS),
            "passing_fpr_budget_count": sum(
                r["candidate"] == name for r in eligible
            ),
        }
    selection = sorted(eligible, key=lambda p: (
        -p["dev_recall_lower95"], p["dev_fpr_upper95"],
        p["cutoff"], p["candidate"],
    ))[0] if eligible else None
    if selection is None:
        return {
            "reason": "NO_CHRONOLOGICAL_SOURCE_DEV_FPR_BUDGET_CANDIDATE",
            "source_fit": dict(train_support), "source_cal": dict(dev_support),
            "selection": None, "candidate_summaries": candidate_summaries,
        }, None, encoder
    return {
        "reason": "CHRONOLOGICAL_SOURCE_DEV_SELECTED_BEFORE_LATER_TEST",
        "source_fit": dict(train_support),
        "source_cal": dict(dev_support),
        "selection": selection,
        "candidate_summaries": candidate_summaries,
    }, candidates[selection["candidate"]][0], encoder


def collect_test_rows(reader, header, seen: set, train_groups: set,
                      estimator, encoder, chosen_cutoff: float, baseline):
    total = Counter()
    baseline_total = Counter()
    day_metrics = defaultdict(lambda: {"candidate": Counter(), "baseline": Counter()})
    by_group = defaultdict(lambda: {"candidate": Counter(), "baseline": Counter()})
    status = Counter()
    flows, labels, dates, group_unseen = [], [], [], []
    test_days = set()
    scanned = 0
    stop = "TAIL_MAX_ROWS"
    def flush():
        if not flows:
            return
        features = [features_v2(flow) for flow in flows]
        new_probs = estimator.predict_proba(encoder.transform(features))[:, 1]
        old_probs = baseline["estimator"].predict_proba(
            baseline["vectorizer"].transform(features)
        )[:, 1]
        if (new_probs.shape != (len(flows),)
                or old_probs.shape != (len(flows),)
                or not np.isfinite(new_probs).all() or not np.isfinite(old_probs).all()):
            raise ValueError("Invalid model inference output")
        for newer, older, y, day, unseen in zip(
            new_probs >= chosen_cutoff, old_probs >= BASELINE_CUTOFF,
            labels, dates, group_unseen
        ):
            cn = ("tp" if y else "fp") if newer else ("fn" if y else "tn")
            co = ("tp" if y else "fp") if older else ("fn" if y else "tn")
            total[cn] += 1
            baseline_total[co] += 1
            day_metrics[day]["candidate"][cn] += 1
            day_metrics[day]["baseline"][co] += 1
            slice_name = "unseen_train_hostpair_proto" if unseen else "seen_train_hostpair_proto"
            by_group[slice_name]["candidate"][cn] += 1
            by_group[slice_name]["baseline"][co] += 1
        flows.clear()
        labels.clear()
        dates.clear()
        group_unseen.clear()
    for cells in islice(reader, TAIL_ROW_LIMIT):
        scanned += 1
        if len(cells) != len(header):
            status["bad_width"] += 1
            continue
        if cells[header.index("log_type")] != "conn":
            status["non_conn"] += 1
            continue
        row = dict(zip(header, cells))
        try:
            f = adapt_v7_conn(row)
        except RowNotEligible:
            status["bad_flow"] += 1
            continue
        if f.timestamp.date() < TEST_MIN or f.timestamp.date() > TEST_MAX:
            status["outside_heldout_dates"] += 1
            continue
        try:
            producer = inspect_untrusted_producer_label(row)
        except RowNotEligible:
            status["bad_label"] += 1
            continue
        key = flow_id(f)
        if key in seen:
            status["exact_identity_duplicate_excluded"] += 1
            continue
        seen.add(key)
        status["eligible_test"] += 1
        day = f.timestamp.date().isoformat()
        test_days.add(day)
        flows.append(f)
        labels.append(producer.producer_class)
        dates.append(day)
        group_unseen.append(group_key(f) not in train_groups)
        if len(flows) >= BATCH:
            flush()
        if status["eligible_test"] >= TARGET_SCORED_ROWS and len(test_days) >= MIN_DAYS:
            stop = "PREDECLARED_TEST_COUNT_AND_THREE_DAYS"
            break
    flush()
    if sum(total.values()) != status["eligible_test"]:
        raise AssertionError("Test confusion != scored test rows")
    if (sum(status[k] for k in (
        "bad_width", "non_conn", "bad_flow", "outside_heldout_dates",
        "bad_label", "exact_identity_duplicate_excluded", "eligible_test"
    )) != scanned):
        raise AssertionError("Tail status accounting differs")
    return {
        "tail_rows_read": scanned,
        "stop_reason": stop,
        "test_eligible_days": sorted(test_days),
        "eligibility": dict(status),
        "candidate_quality": _quality(total),
        "baseline_on_identical_rows": _quality(baseline_total),
        "per_day": {
            day: {name: _quality(c) for name, c in metrics.items()}
            for day, metrics in sorted(day_metrics.items())
        },
        "train_hostpair_overlap_slices": {
            key: {name: _quality(c) for name, c in metrics.items()}
            for key, metrics in sorted(by_group.items())
        },
    }


def run(archive: Path, baseline_path: Path, output: Path,
        *, candidate_out: Path | None = None):
    if (archive.name != "iot_dataset_v7.zip"
            or archive.stat().st_size != TARGET_SIZE
            or digest(archive) != TARGET_SHA
            or digest(baseline_path) != MODEL_SHA):
        raise ValueError("Original source/baseline SHA mismatch")
    if output.exists():
        raise ValueError("Evidence overwrite refused")
    with zipfile.ZipFile(archive, "r", allowZip64=True) as zf:
        members = zf.infolist()
        if (len(members) != 1 or members[0].filename != "iot_dataset_v7.csv"
                or members[0].file_size != 13_561_863_941
                or members[0].flag_bits & 1):
            raise ValueError("ZIP member rejected")
        with zf.open(members[0], "r") as raw:
            with io.TextIOWrapper(raw, encoding="utf-8-sig", newline="") as source:
                old_csv_limit = csv.field_size_limit()
                csv.field_size_limit(131072)
                try:
                    reader = csv.reader(source, strict=True)
                    header = next(reader)
                    verify_exact_header(header)
                    seen = set()
                    flow_prefix, producer_y, source_stats = read_partition(
                        reader, header, EVAL_END, seen=seen
                    )
                    fit_i = [
                        i for i, flow in enumerate(flow_prefix)
                        if flow.timestamp.date() <= TRAIN_MAX
                    ]
                    dev_i = [
                        i for i, flow in enumerate(flow_prefix)
                        if flow.timestamp.date() == CAL_DATE
                    ]
                    fit_flows = [flow_prefix[i] for i in fit_i]
                    dev_flows = [flow_prefix[i] for i in dev_i]
                    fit_y = producer_y[fit_i]
                    dev_y = producer_y[dev_i]
                    group_source = {group_key(flow) for flow in fit_flows}
                    dev_train_overlap = sum(
                        group_key(flow) in group_source for flow in dev_flows
                    )
                    decision, chosen, encoder = choose_on_exposed_apr10(
                        fit_flows, fit_y, dev_flows, dev_y,
                    )
                    del flow_prefix, producer_y, fit_flows, dev_flows
                    if chosen is None:
                        return {
                            "status": "SOURCE_DAY_DEV_NO_GO_NO_TEST_UNBLINDED",
                            "source_prefix_stats": dict(source_stats),
                            "day_selection": decision,
                            "source_day_train_dev_group_overlap": dev_train_overlap,
                            "tail_rows_read": 0,
                            "operational_ml_p0": "NO_GO",
                        }
                    baseline = joblib.load(baseline_path)
                    if (baseline.get("fixed_cutoff") != BASELINE_CUTOFF
                            or baseline.get("feature_contract")
                            != "missingness_aware_flow_v2"):
                        raise ValueError("Frozen original baseline protocol changed")
                    test = collect_test_rows(
                        reader, header, seen, group_source, chosen, encoder,
                        decision["selection"]["cutoff"], baseline
                    )
                finally:
                    csv.field_size_limit(old_csv_limit)
    results = test["candidate_quality"]
    supported = (
        results.get("benign", 0) >= MIN_TEST_BENIGN
        and results.get("attack", 0) >= MIN_TEST_ATTACK
        and len(test["test_eligible_days"]) >= MIN_DAYS
    )
    pointwise_pass = bool(
        supported and results.get("fpr_upper_95") is not None
        and results.get("recall_lower_95") is not None
        and results["fpr_upper_95"] <= RESEARCH_FPR_UPPER
        and results["recall_lower_95"] >= RESEARCH_RECALL_LOWER
    )
    report = {
        "status": "CHRONOLOGICALLY_FENCED_SAME_LAB_RESEARCH_TRANSFER",
        "model_candidate_kind": decision["selection"]["candidate"],
        "decision_threshold": decision["selection"]["cutoff"],
        "development_fit_days": "through_2025-04-08",
        "development_calibration_day": "2025-04-10",
        "evaluation_days": "2025-04-12_through_2025-04-17",
        "source_prefix_previously_exposed_rows": EVAL_END,
        "source_prefix_stats": dict(source_stats),
        "source_day_train_dev_group_overlap": dev_train_overlap,
        "source_day_selection": decision,
        "time_fenced_test": test,
        "pointwise_producer_label_numeric_targets_met": pointwise_pass,
        "pointwise_research_gate_independently_verified": False,
        "cluster_day_uncertainty_requires_review": True,
        "exact_original_dataset_sha256": TARGET_SHA,
        "original_frozen_baseline_sha256": MODEL_SHA,
        "original_baseline_threshold": BASELINE_CUTOFF,
        "new_model_trained_from_user_authorized_public_lab_source": True,
        "future_test_labels_never_used_to_select_model_or_cutoff": True,
        "source_group_overlap_and_same_lab_caveat": True,
        "human_adjudicated_ground_truth": False,
        "independent_operational_site": False,
        "signed_production_model": False,
        "full_operational_ml_p0": "NO_GO",
    }
    if candidate_out is not None:
        if candidate_out.exists() or candidate_out.is_symlink():
            raise ValueError("Do not overwrite independent candidate artifact")
        bundle = {
            "schema_version": 2,
            "research_only": True,
            "production_approved": False,
            "feature_contract": "missingness_aware_flow_v2",
            "dataset": "IoT-SFC v7 same-lab, user-reported citation-authorized",
            "dataset_sha256": TARGET_SHA,
            "training_dates": "through_2025-04-08",
            "source_dev_date": "2025-04-10",
            "heldout_test_dates_not_used_in_fit_or_selection": "2025-04-12_2025-04-17",
            "cutoff": decision["selection"]["cutoff"],
            "candidate": decision["selection"]["candidate"],
            "vectorizer": encoder,
            "estimator": chosen,
            "scikit_learn_version": sklearn.__version__,
        }
        candidate_out.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(candidate_out, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            joblib.dump(bundle, stream, compress=3)
        report["unsigned_research_candidate_sha256"] = digest(candidate_out)
        report["unsigned_research_candidate_status"] = "NOT_APPROVED_NOT_SIGNED"
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--candidate-out", type=Path)
    args = p.parse_args()
    result = run(args.archive, args.baseline, args.report,
                 candidate_out=args.candidate_out)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.report, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as dest:
        json.dump(result, dest, indent=2, sort_keys=True, allow_nan=False)
        dest.write("\n")
    print(json.dumps({
        "status": result["status"],
        "chosen": result.get("model_candidate_kind"),
        "candidate": result.get("time_fenced_test", {}).get("candidate_quality"),
        "baseline": result.get("time_fenced_test", {}).get("baseline_on_identical_rows"),
        "pointwise_producer_targets": result.get("pointwise_producer_label_numeric_targets_met"),
        "p0_operational": "NO_GO",
    }))


if __name__ == "__main__":
    main()
