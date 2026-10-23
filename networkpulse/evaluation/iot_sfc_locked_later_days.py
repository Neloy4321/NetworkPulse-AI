"""Independent chronological *slice* stress of already frozen IoT-SFC v7 ExtraTrees.

Does NOT train, recalibrate, select features/models, sign, deploy, or claim P0.
Fixed April 15-17 time fence, first 60k valid unique conn rows per UTC day
within a fixed 9M-row CSV scan after the exposed 450k source prefix.
Same public laboratory and producer labels; no field-site approval.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import math
import os
import zipfile
from collections import Counter, defaultdict
from datetime import date, datetime, timezone
from itertools import islice
from pathlib import Path

import joblib
import numpy as np
import sklearn

from networkpulse.evaluation.iot_sfc_frozen_score import digest, adapt_v7_conn
from networkpulse.evaluation.iot_sfc_preregistration import TARGET_SHA, TARGET_SIZE
from networkpulse.evaluation.iot_sfc_v7_conn_adapter import (
    RowNotEligible, inspect_untrusted_producer_label, verify_exact_header,
)
from networkpulse.feature_contract_v2 import features_v2
from networkpulse.generalization_evidence import wilson_interval

MODEL_SHA = "ecc320bc693481fc45b143b48ffbebcb117899e888e4687930f3361501af6fa1"
CUTOFF = 0.9
DATA_MEM = "iot_dataset_v7.csv"
FIT_DEV_PREFIX_EXCLUDED = 450_000
SCAN_ROWS_AFTER_PREFIX = 9_000_000
MAX_PER_DAY = 60_000
BATCH_SIZE = 2048
TEST_DAYS = (date(2025, 4, 15), date(2025, 4, 16), date(2025, 4, 17))
PASS_FPR_UPPER = 0.05
PASS_RECALL_LOWER = 0.80


def verify_source_and_model(archive: Path, model_file: Path) -> dict:
    if archive.name != "iot_dataset_v7.zip" or archive.stat().st_size != TARGET_SIZE:
        raise ValueError("Source name/size unexpected")
    if digest(archive) != TARGET_SHA or digest(model_file) != MODEL_SHA:
        raise ValueError("Original source/candidate SHA mismatch")
    if sklearn.__version__ != "1.9.1":
        raise ValueError("Original candidate sklearn 1.9.1 runtime required")
    # Only model from the original trusted GitHub Actions artifact 12487143959,
    # SHA-verified before pickle deserialization. Never load arbitrary files.
    candidate = joblib.load(model_file)
    if (candidate.get("schema_version") != 2
            or candidate.get("research_only") is not True
            or candidate.get("production_approved") is not False
            or candidate.get("dataset_sha256") != TARGET_SHA
            or candidate.get("candidate") != "extra_trees"
            or candidate.get("cutoff") != CUTOFF
            or candidate.get("training_dates") != "through_2025-04-08"
            or candidate.get("source_dev_date") != "2025-04-10"
            or candidate.get("heldout_test_dates_not_used_in_fit_or_selection")
            != "2025-04-12_2025-04-17"
            or candidate.get("feature_contract") != "missingness_aware_flow_v2"
            or candidate.get("scikit_learn_version") != sklearn.__version__):
        raise ValueError("Candidate artifact protocol changed")
    return candidate


def summarize_confusion(counts: Counter) -> dict:
    tn, fp, fn, tp = (int(counts[k]) for k in ("tn", "fp", "fn", "tp"))
    benign, attack = tn + fp, fn + tp
    fpr = fp / benign if benign else None
    recall = tp / attack if attack else None
    upper = wilson_interval(fp, benign)[1] if benign else None
    lower = wilson_interval(tp, attack)[0] if attack else None
    adequate_support = benign >= 200 and attack >= 100
    return {
        "confusion": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "benign": benign, "attack": attack,
        "fpr": fpr, "fpr_wilson_upper95": upper,
        "recall": recall, "recall_wilson_lower95": lower,
        "numerical_gates_descriptively_met": (
            bool(adequate_support and upper <= PASS_FPR_UPPER
                 and lower >= PASS_RECALL_LOWER)
        ),
        "independent_ground_truth": False,
        "external_field_acceptance": False,
    }


def run(archive: Path, model: Path) -> dict:
    candidate = verify_source_and_model(archive, model)
    metrics = defaultdict(Counter)
    stats = Counter()
    counted = Counter()
    dedup = set()
    batch, labs, days = [], [], []

    def flush():
        if not batch:
            return
        X = candidate["vectorizer"].transform([features_v2(x) for x in batch])
        pred = candidate["estimator"].predict_proba(X)
        if pred.shape != (len(batch), 2) or not np.isfinite(pred).all():
            raise ValueError("Invalid probabilities from signed-but-not-approved candidate")
        for prob, label, day in zip(pred[:, 1], labs, days):
            pos = bool(prob >= CUTOFF)
            cell = ("tp" if label else "fp") if pos else ("fn" if label else "tn")
            metrics[day][cell] += 1
        batch.clear()
        labs.clear()
        days.clear()

    with zipfile.ZipFile(archive, "r", allowZip64=True) as container:
        infos = container.infolist()
        if (len(infos) != 1 or infos[0].filename != DATA_MEM
                or infos[0].file_size != 13_561_863_941
                or infos[0].flag_bits & 1 or infos[0].is_dir()):
            raise ValueError("Expected exactly original unencrypted CSV member")
        with container.open(infos[0], "r") as raw:
            with io.TextIOWrapper(raw, encoding="utf-8-sig", newline="") as handle:
                old_limit = csv.field_size_limit()
                csv.field_size_limit(131_072)
                try:
                    reader = csv.reader(handle, strict=True)
                    header = next(reader)
                    verify_exact_header(header)
                    indices = {key: header.index(key) for key in ("log_type", "ts")}
                    for values in islice(
                        reader, FIT_DEV_PREFIX_EXCLUDED,
                        FIT_DEV_PREFIX_EXCLUDED + SCAN_ROWS_AFTER_PREFIX,
                    ):
                        stats["rows_read_after_prefix"] += 1
                        if len(values) != len(header):
                            stats["bad_row_width"] += 1
                            continue
                        if values[indices["log_type"]] != "conn":
                            stats["non_conn"] += 1
                            continue
                        try:
                            stamp = float(values[indices["ts"]])
                            if not math.isfinite(stamp):
                                raise ValueError
                            day_value = datetime.fromtimestamp(
                                stamp, timezone.utc
                            ).date()
                        except (ValueError, OverflowError, OSError):
                            stats["invalid_timestamp"] += 1
                            continue
                        if day_value not in TEST_DAYS:
                            stats["outside_predeclared_days"] += 1
                            continue
                        day = day_value.isoformat()
                        if counted[day] >= MAX_PER_DAY:
                            stats["per_day_prefix_cap"] += 1
                            continue
                        row = dict(zip(header, values))
                        try:
                            flow = adapt_v7_conn(row)
                        except RowNotEligible:
                            stats["invalid_flow"] += 1
                            continue
                        try:
                            evidence = inspect_untrusted_producer_label(row)
                        except RowNotEligible:
                            stats["invalid_producer_label"] += 1
                            continue
                        identity = (
                            flow.uid, flow.timestamp, str(flow.src_ip),
                            str(flow.dst_ip), flow.src_port, flow.dst_port, flow.proto
                        )
                        if identity in dedup:
                            stats["duplicate_flow"] += 1
                            continue
                        dedup.add(identity)
                        counted[day] += 1
                        stats["scored_flow"] += 1
                        batch.append(flow)
                        labs.append(evidence.producer_class)
                        days.append(day)
                        if len(batch) >= BATCH_SIZE:
                            flush()
                    flush()
                finally:
                    csv.field_size_limit(old_limit)
    aggregated = Counter()
    for counts in metrics.values():
        aggregated.update(counts)
    if sum(aggregated.values()) != stats["scored_flow"]:
        raise ValueError("Scored rows disagree with aggregate confusion")
    if sum(stats.values()) - stats["rows_read_after_prefix"] != stats["rows_read_after_prefix"]:
        raise ValueError("Unreconciled source row accounting")
    result = {
        "status": "POST_LOCK_APR15_17_SAME_PUBLIC_LAB_PRODUCER_LABEL_STRESS",
        "frozen_unsigned_research_model_sha256": MODEL_SHA,
        "fixed_cutoff": CUTOFF,
        "dataset_sha256": TARGET_SHA,
        "trained_or_selected_on_apr15_17": False,
        "scan_cap_after_source_prefix": SCAN_ROWS_AFTER_PREFIX,
        "source_prefix_excluded": FIT_DEV_PREFIX_EXCLUDED,
        "per_day_max_eligible_prefix": MAX_PER_DAY,
        "predeclared_target_days": [x.isoformat() for x in TEST_DAYS],
        "source_scan": dict(sorted(stats.items())),
        "day_samples": dict(sorted(counted.items())),
        "combined": summarize_confusion(aggregated),
        "by_day": {day: summarize_confusion(c) for day, c in sorted(metrics.items())},
        "producer_labels_independently_adjudicated": False,
        "cross_day_or_site_cluster_aware_ci_verified": False,
        "unseen_attack_hostpair_support_verified": False,
        "genuinely_independent_site": False,
        "signed_active_production_v2_deployment_verified": False,
        "operational_ml_p0": "NO_GO",
    }
    return result


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", required=True, type=Path)
    p.add_argument("--model", required=True, type=Path)
    p.add_argument("--report", required=True, type=Path)
    opt = p.parse_args()
    if opt.report.exists() or opt.report.is_symlink():
        p.error("Refuse evidence overwrite")
    result = run(opt.archive, opt.model)
    opt.report.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(opt.report, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(result, out, sort_keys=True, indent=2, allow_nan=False)
        out.write("\n")
    print(json.dumps({
        "status": result["status"], "rows": result["source_scan"]["scored_flow"],
        "candidate": result["combined"], "operational_p0": "NO_GO",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
