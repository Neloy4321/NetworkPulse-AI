"""Controlled MQTT recall repair candidates on EXPOSED IoT-SFC laboratory data.

Training uses the source April 3-8 days; cutoff selection excludes host/proto
groups overlapping the April 10 development day. The April 15-17 slice is
already exposed and may only be called a research stress diagnostic. No model
is promoted, signed or exported by this script.
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

import numpy as np
import sklearn
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer

from networkpulse.evaluation import iot_sfc_locked_later_days as locked
from networkpulse.evaluation.iot_sfc_frozen_score import adapt_v7_conn
from networkpulse.evaluation.iot_sfc_v7_conn_adapter import (
    RowNotEligible, inspect_untrusted_producer_label, verify_exact_header,
)
from networkpulse.feature_contract_v2 import FlowV2, features_v2
from networkpulse.generalization_evidence import wilson_interval

SEED = 1729
SOURCE_ROWS = 450_000
FIT_LAST_DAY = date(2025, 4, 8)
DEV_DAY = date(2025, 4, 10)
CUTOFFS = (0.30, 0.40, 0.50, 0.60, 0.70, 0.75, 0.80, 0.85, 0.90)
STABLE_PORTS = frozenset((21, 22, 23, 53, 80, 123, 443, 1883, 3389, 8080, 8883))
STATES = frozenset(("s0", "s1", "sf", "rej", "rsto", "rstr", "rstos0", "rstrh", "sh", "shr", "oth"))


def features_repair(flow: FlowV2) -> dict[str, float]:
    """Leak-free, versioned research-only extension of the V2 flow features."""
    out = features_v2(flow)
    service = (f"port_{flow.dst_port}" if flow.dst_port in STABLE_PORTS
               else "other_well_known" if flow.dst_port < 1024
               else "other_registered" if flow.dst_port < 49152
               else "dynamic")
    state = flow.conn_state if flow.conn_state in STATES else "other"
    out[f"research_service={service}"] = 1.0
    out[f"research_state={state}"] = 1.0
    return out


def group_key(flow: FlowV2) -> tuple:
    return (str(flow.src_ip), str(flow.dst_ip), flow.proto)


def source_data(reader, header) -> tuple[list, np.ndarray, list, Counter]:
    flows, labels, families = [], [], []
    stats = Counter()
    dedup = set()
    for cells in islice(reader, SOURCE_ROWS):
        stats["raw_rows"] += 1
        if len(cells) != len(header):
            stats["bad_width"] += 1
            continue
        if cells[header.index("log_type")] != "conn":
            stats["non_conn"] += 1
            continue
        row = dict(zip(header, cells))
        try:
            flow = adapt_v7_conn(row)
            evidence = inspect_untrusted_producer_label(row)
        except RowNotEligible:
            stats["ineligible"] += 1
            continue
        identity = (flow.uid, flow.timestamp, str(flow.src_ip), str(flow.dst_ip),
                    flow.src_port, flow.dst_port, flow.proto)
        if identity in dedup:
            stats["duplicate"] += 1
            continue
        dedup.add(identity)
        flows.append(flow)
        labels.append(evidence.producer_class)
        families.append(family(row) if evidence.producer_class else "benign")
    if stats["raw_rows"] != SOURCE_ROWS:
        raise ValueError("Original source prefix incomplete")
    return flows, np.asarray(labels, dtype=np.int8), families, stats


def family(row: dict) -> str:
    value = str(row.get("type_of_attack") or "").strip().lower()
    if value in ("mqtt_malformed", "mqtt_brute_force", "synflood"):
        return value
    return "other_attack_family"


def confusion(truth, predicted) -> Counter:
    return Counter({
        "tn": int(np.sum((truth == 0) & (~predicted))),
        "fp": int(np.sum((truth == 0) & predicted)),
        "fn": int(np.sum((truth == 1) & (~predicted))),
        "tp": int(np.sum((truth == 1) & predicted)),
    })


def frozen_or_repair(old_probability: float, new_probability: float,
                     new_cutoff: float) -> bool:
    """Research-only OR; the frozen cutoff remains fixed at its original 0.90.

    This rule is *not* a selected or qualified production decision rule: the
    April 15-17 labels were already exposed when this rule was examined.
    """
    return old_probability >= locked.CUTOFF or new_probability >= new_cutoff


def candidate_selection(trained: dict, truth) -> dict:
    """Only unshared April 10 groups may select the candidate/cutoff."""
    n0, n1 = int(np.sum(truth == 0)), int(np.sum(truth == 1))
    if n0 < 200 or n1 < 100:
        return {"selected": None, "reason": "GROUP_DISJOINT_DEV_UNDERPOWERED",
                "dev_benign": n0, "dev_attack": n1, "options": []}
    records = []
    for name, probs in trained.items():
        for cutoff in CUTOFFS:
            cm = confusion(truth, probs >= cutoff)
            upper = wilson_interval(cm["fp"], n0)[1]
            lower = wilson_interval(cm["tp"], n1)[0]
            records.append({
                "name": name, "cutoff": cutoff,
                "fpr_upper95": upper, "recall_lower95": lower,
                "eligible": upper <= 0.03 and lower >= 0.80,
                "confusion": dict(cm),
            })
    qualified = [row for row in records if row["eligible"]]
    chosen = (sorted(qualified, key=lambda x: (
        -x["recall_lower95"], x["fpr_upper95"], -x["cutoff"], x["name"]
    ))[0] if qualified else None)
    return {"selected": chosen, "reason": "QUALIFIED_SOURCE_DEV" if chosen
            else "NO_JOINT_SOURCE_DEV_QUALIFIED_CANDIDATE",
            "dev_benign": n0, "dev_attack": n1, "options": records}


def fit_source(flows, y, families):
    fit_idx = [i for i, f in enumerate(flows) if f.timestamp.date() <= FIT_LAST_DAY]
    day_dev = [i for i, f in enumerate(flows) if f.timestamp.date() == DEV_DAY]
    fit_groups = {group_key(flows[i]) for i in fit_idx}
    dev_idx = [i for i in day_dev if group_key(flows[i]) not in fit_groups]
    if min(int(np.sum(y[fit_idx] == c)) for c in (0, 1)) < 200:
        raise ValueError("SOURCE_FIT_CLASS_SUPPORT_INSUFFICIENT")
    vectorizer = DictVectorizer(sparse=False)
    Xfit = vectorizer.fit_transform([features_repair(flows[i]) for i in fit_idx])
    Xdev = (vectorizer.transform([features_repair(flows[i]) for i in dev_idx])
            if dev_idx else None)
    options = {
        "extra_repair": ExtraTreesClassifier(
            n_estimators=180, max_depth=18, min_samples_leaf=5,
            class_weight="balanced_subsample", random_state=SEED, n_jobs=2,
        ),
        "rf_repair": RandomForestClassifier(
            n_estimators=180, max_depth=18, min_samples_leaf=5,
            class_weight="balanced_subsample", random_state=SEED, n_jobs=2,
        ),
    }
    trained = {name: model.fit(Xfit, y[fit_idx]) for name, model in options.items()}
    scores = ({name: model.predict_proba(Xdev)[:, 1]
               for name, model in trained.items()} if Xdev is not None else {})
    selection = candidate_selection(scores, y[dev_idx])
    # Fixed, explicitly unqualified fallback for exploratory stress when there
    # is insufficient nonoverlapping source development evidence.
    choice = selection["selected"]
    selected_name = choice["name"] if choice else "extra_repair"
    selected_cutoff = choice["cutoff"] if choice else 0.80
    stats = {
        "source_fit": {"benign": int(np.sum(y[fit_idx] == 0)),
                       "attack": int(np.sum(y[fit_idx] == 1)),
                       "attack_families": dict(Counter(
                           families[i] for i in fit_idx if y[i] == 1))},
        "source_dev": {"raw_day_rows": len(day_dev),
                       "fit_group_overlap_excluded": len(day_dev) - len(dev_idx),
                       "nonoverlap_rows": len(dev_idx),
                       "attack_families_nonoverlap": dict(Counter(
                           families[i] for i in dev_idx if y[i] == 1))},
        "selection": selection,
        "chosen_candidate": selected_name,
        "chosen_cutoff": selected_cutoff,
        "chosen_source_dev_qualified": choice is not None,
    }
    return vectorizer, trained[selected_name], selected_cutoff, stats


def stress(reader, header, original, encoder, model, cutoff):
    day_counts = defaultdict(Counter)
    family_counts = defaultdict(Counter)
    or_day_counts = defaultdict(Counter)
    or_family_counts = defaultdict(Counter)
    or_overlap = Counter()
    original_counts = Counter()
    stats = Counter()
    counts = Counter()
    identities = set()
    flows, labs, days, families = [], [], [], []

    def flush():
        if not flows:
            return
        new = model.predict_proba(encoder.transform([features_repair(f) for f in flows]))
        old = original["estimator"].predict_proba(original["vectorizer"].transform(
            [features_v2(f) for f in flows]
        ))
        if (new.shape != (len(flows), 2) or old.shape != (len(flows), 2)
                or not np.isfinite(new).all() or not np.isfinite(old).all()):
            raise ValueError("Invalid model probabilities")
        for current, previous, y, day, fam in zip(new[:, 1], old[:, 1],
                                                   labs, days, families):
            cell = ("tp" if y else "fp") if current >= cutoff else ("fn" if y else "tn")
            oldcell = ("tp" if y else "fp") if previous >= locked.CUTOFF else (
                "fn" if y else "tn"
            )
            old_flag = previous >= locked.CUTOFF
            new_flag = current >= cutoff
            fused_flag = frozen_or_repair(previous, current, cutoff)
            fused_cell = ("tp" if y else "fp") if fused_flag else ("fn" if y else "tn")
            day_counts[day][cell] += 1
            family_counts[fam][cell] += 1
            or_day_counts[day][fused_cell] += 1
            or_family_counts[fam][fused_cell] += 1
            or_overlap[("attack" if y else "benign") + "|" + (
                "both" if old_flag and new_flag else
                "frozen_only" if old_flag else
                "repair_only" if new_flag else "neither"
            )] += 1
            original_counts[oldcell] += 1
        flows.clear()
        labs.clear()
        days.clear()
        families.clear()

    for cells in islice(reader, locked.SCAN_ROWS_AFTER_PREFIX):
        stats["scanned"] += 1
        if len(cells) != len(header) or cells[header.index("log_type")] != "conn":
            continue
        try:
            epoch = float(cells[header.index("ts")])
            if not math.isfinite(epoch):
                continue
            day_value = datetime.fromtimestamp(epoch, timezone.utc).date()
        except (ValueError, OverflowError, OSError):
            continue
        if day_value not in locked.TEST_DAYS:
            continue
        day = day_value.isoformat()
        if counts[day] >= locked.MAX_PER_DAY:
            continue
        row = dict(zip(header, cells))
        try:
            flow = adapt_v7_conn(row)
            evidence = inspect_untrusted_producer_label(row)
        except RowNotEligible:
            continue
        identity = (flow.uid, flow.timestamp, str(flow.src_ip), str(flow.dst_ip),
                    flow.src_port, flow.dst_port, flow.proto)
        if identity in identities:
            continue
        identities.add(identity)
        counts[day] += 1
        flows.append(flow)
        labs.append(evidence.producer_class)
        days.append(day)
        families.append(family(row) if evidence.producer_class else "benign")
        if len(flows) >= locked.BATCH_SIZE:
            flush()
    flush()
    if dict(original_counts) != {"tn": 155221, "fp": 119, "fn": 432, "tp": 590}:
        raise ValueError("Original locked 0.90 metrics did not replay identically")
    combined = Counter()
    for sub in day_counts.values():
        combined.update(sub)
    or_combined = Counter()
    for sub in or_day_counts.values():
        or_combined.update(sub)
    if sum(combined.values()) != 156362:
        raise ValueError("Exposed stress sample support changed")
    if sum(or_combined.values()) != sum(combined.values()):
        raise ValueError("OR aggregation lost or duplicated research rows")
    if or_combined["fn"] > original_counts["fn"]:
        raise ValueError("OR rule unexpectedly lost a frozen-model positive")
    return {
        "source_scan_rows": stats["scanned"],
        "counts_by_day": dict(sorted(counts.items())),
        "original_locked_comparison": dict(original_counts),
        "candidate_combined": locked.summarize_confusion(combined),
        "candidate_per_day": {k: locked.summarize_confusion(v)
                              for k, v in sorted(day_counts.items())},
        "candidate_by_producer_family": {k: locked.summarize_confusion(v)
                                         for k, v in sorted(family_counts.items())},
        "frozen_or_repair_research_only": {
            "rule": "frozen_probability_ge_0.90_OR_repair_probability_ge_source_cutoff",
            "selection_is_independently_qualified": False,
            "already_exposed_same_lab_labels": True,
            "combined": locked.summarize_confusion(or_combined),
            "per_day": {k: locked.summarize_confusion(v)
                        for k, v in sorted(or_day_counts.items())},
            "by_producer_family": {k: locked.summarize_confusion(v)
                                   for k, v in sorted(or_family_counts.items())},
            "joint_prediction_overlap": dict(sorted(or_overlap.items())),
        },
    }


def run(archive: Path, original_path: Path):
    original = locked.verify_source_and_model(archive, original_path)
    if sklearn.__version__ != "1.9.1":
        raise ValueError("Pinned source candidate runtime changed")
    with zipfile.ZipFile(archive, "r", allowZip64=True) as zf:
        members = zf.infolist()
        if (len(members) != 1 or members[0].filename != locked.DATA_MEM
                or members[0].file_size != 13_561_863_941 or members[0].flag_bits & 1):
            raise ValueError("Original ZIP member identity changed")
        with zf.open(members[0], "r") as raw:
            with io.TextIOWrapper(raw, encoding="utf-8-sig", newline="") as text:
                previous_limit = csv.field_size_limit()
                csv.field_size_limit(131_072)
                try:
                    reader = csv.reader(text, strict=True)
                    header = next(reader)
                    verify_exact_header(header)
                    flows, y, families, source_stats = source_data(reader, header)
                    encoder, chosen, cutoff, choice = fit_source(flows, y, families)
                    del flows, y, families
                    comparison = stress(reader, header, original, encoder, chosen, cutoff)
                finally:
                    csv.field_size_limit(previous_limit)
    return {
        "status": "P0_MQTT_FEATURE_REPAIR_EXPOSED_SAME_LAB_RESEARCH_ONLY",
        "original_source_sha256": locked.TARGET_SHA,
        "original_frozen_model_sha256": locked.MODEL_SHA,
        "research_feature_contract": "missingness_aware_flow_v2_plus_stable_service_and_state_research",
        "source_prefix_stats": dict(source_stats),
        "fit_dev": choice,
        "exposed_stress": comparison,
        "attack_labels_independently_adjudicated": False,
        "new_independent_test_used": False,
        "model_exported_or_signed": False,
        "operational_ml_p0": "NO_GO",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--original-model", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists() or args.report.is_symlink():
        parser.error("Never overwrite research evidence")
    result = run(args.archive, args.original_model)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.report, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as dest:
        json.dump(result, dest, sort_keys=True, indent=2, allow_nan=False)
        dest.write("\n")
    print(json.dumps({"status": result["status"],
                      "stress": result["exposed_stress"]["candidate_combined"],
                      "operational_ml_p0": "NO_GO"}))


if __name__ == "__main__":
    main()
