"""Aggregate-only diagnosis of the EXPOSED IoT-SFC April 15-17 Recall failure.

This is not a fresh holdout, model selection, label adjudication or acceptance.
It deliberately replays the immutable locked experiment's sampling protocol.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import math
import os
import re
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path

import numpy as np

from networkpulse.evaluation import iot_sfc_locked_later_days as locked
from networkpulse.evaluation.iot_sfc_frozen_score import adapt_v7_conn
from networkpulse.evaluation.iot_sfc_v7_conn_adapter import (
    RowNotEligible, inspect_untrusted_producer_label, verify_exact_header,
)
from networkpulse.feature_contract_v2 import features_v2

SCORE_CUTOFFS = (0.50, 0.70, 0.80, 0.85, 0.90, 0.95)
MIN_PUBLISHED_SLICE = 10
SAFE_CATEGORY = re.compile(r"^[A-Za-z0-9_ .:/+-]{1,48}$")
COUNTERS = ("duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts")
PINNED_CONFUSION = {"tn": 155221, "fp": 119, "fn": 432, "tp": 590}
PINNED_APR15 = {"tn": 59387, "fp": 44, "fn": 419, "tp": 150}


def category(value: object) -> str:
    """Allow only bounded categorical labels, never host or session identifiers."""
    candidate = str(value or "").strip()
    if not SAFE_CATEGORY.fullmatch(candidate):
        return "unclassified"
    if re.search(r"(?:\d{1,3}\.){3}\d{1,3}|@|\\", candidate):
        return "unclassified"
    return candidate.lower()


def service(flow) -> str:
    if flow.dst_port in {21, 22, 23, 53, 80, 123, 443, 1883, 3389, 8080, 8883}:
        return f"port_{flow.dst_port}"
    if flow.dst_port < 1024:
        return "other_well_known"
    if flow.dst_port < 49152:
        return "other_registered"
    return "dynamic"


def row_slices(flow, row: dict, day: str, label: int) -> dict[str, str]:
    values = {
        "day": day,
        "protocol": flow.proto,
        "service": service(flow),
        "connection_state": category(flow.conn_state),
        "missingness": "".join("1" if getattr(flow, c) is None else "0" for c in COUNTERS),
    }
    if label:
        family = category(row.get("type_of_attack"))
        values["attack_family"] = family
        values["day_attack_family"] = f"{day}:{family}"
    return values


def record(aggregate, slices, cutoff_counts, *, flow, row, day, label, score):
    if not 0 <= score <= 1 or not math.isfinite(score):
        raise ValueError("Nonfinite or invalid inference probability")
    for cutoff in SCORE_CUTOFFS:
        detected = score >= cutoff
        cell = ("tp" if label else "fp") if detected else ("fn" if label else "tn")
        cutoff_counts[cutoff][cell] += 1
    cell = ("tp" if label else "fp") if score >= locked.CUTOFF else (
        "fn" if label else "tn"
    )
    aggregate[cell] += 1
    for kind, key in row_slices(flow, row, day, label).items():
        slices[kind][key][cell] += 1


def publish_slices(slices) -> dict:
    result = {}
    for kind, categories in sorted(slices.items()):
        entries = {}
        suppressed = Counter()
        for key, counts in sorted(categories.items()):
            if sum(counts.values()) < MIN_PUBLISHED_SLICE:
                suppressed.update(counts)
            else:
                entries[key] = locked.summarize_confusion(counts)
        if suppressed:
            entries["other_rare_categories"] = locked.summarize_confusion(suppressed)
        result[kind] = entries
    return result


def run(archive: Path, model: Path) -> dict:
    candidate = locked.verify_source_and_model(archive, model)
    aggregate = Counter()
    cutoff_counts = defaultdict(Counter)
    slices = defaultdict(lambda: defaultdict(Counter))
    stats = Counter()
    counted = Counter()
    identities = set()
    flows, rows, labels, days = [], [], [], []

    def flush():
        if not flows:
            return
        X = candidate["vectorizer"].transform([features_v2(flow) for flow in flows])
        probs = candidate["estimator"].predict_proba(X)
        if probs.shape != (len(flows), 2) or not np.isfinite(probs).all():
            raise ValueError("Malformed inference probabilities")
        for flow, row, label, day, score in zip(flows, rows, labels, days, probs[:, 1]):
            record(aggregate, slices, cutoff_counts, flow=flow, row=row,
                   day=day, label=label, score=float(score))
        flows.clear()
        rows.clear()
        labels.clear()
        days.clear()

    with zipfile.ZipFile(archive, "r", allowZip64=True) as zf:
        members = zf.infolist()
        if (len(members) != 1 or members[0].filename != locked.DATA_MEM
                or members[0].file_size != 13_561_863_941
                or members[0].flag_bits & 1 or members[0].is_dir()):
            raise ValueError("Original ZIP member not verified")
        with zf.open(members[0], "r") as raw:
            with io.TextIOWrapper(raw, encoding="utf-8-sig", newline="") as handle:
                old = csv.field_size_limit()
                csv.field_size_limit(131_072)
                try:
                    reader = csv.reader(handle, strict=True)
                    header = next(reader)
                    verify_exact_header(header)
                    column = {k: header.index(k) for k in ("log_type", "ts")}
                    for cells in islice(reader, locked.FIT_DEV_PREFIX_EXCLUDED,
                                        locked.FIT_DEV_PREFIX_EXCLUDED
                                        + locked.SCAN_ROWS_AFTER_PREFIX):
                        stats["scanned"] += 1
                        if len(cells) != len(header):
                            continue
                        if cells[column["log_type"]] != "conn":
                            continue
                        try:
                            stamp = float(cells[column["ts"]])
                            if not math.isfinite(stamp):
                                continue
                            actual_day = datetime.fromtimestamp(
                                stamp, timezone.utc
                            ).date()
                        except (ValueError, OSError, OverflowError):
                            continue
                        if actual_day not in locked.TEST_DAYS:
                            continue
                        day = actual_day.isoformat()
                        if counted[day] >= locked.MAX_PER_DAY:
                            continue
                        row = dict(zip(header, cells))
                        try:
                            flow = adapt_v7_conn(row)
                            evidence = inspect_untrusted_producer_label(row)
                        except RowNotEligible:
                            continue
                        identity = (flow.uid, flow.timestamp, str(flow.src_ip),
                                    str(flow.dst_ip), flow.src_port, flow.dst_port,
                                    flow.proto)
                        if identity in identities:
                            continue
                        identities.add(identity)
                        counted[day] += 1
                        flows.append(flow)
                        # Store only categorical metadata needed for a bounded batch.
                        rows.append({"type_of_attack": row.get("type_of_attack")})
                        labels.append(evidence.producer_class)
                        days.append(day)
                        if len(flows) >= locked.BATCH_SIZE:
                            flush()
                    flush()
                finally:
                    csv.field_size_limit(old)
    if dict(aggregate) != PINNED_CONFUSION:
        raise ValueError("Replay differs from immutable April15-17 confusion")
    april15 = slices["day"]["2025-04-15"]
    if dict(april15) != PINNED_APR15:
        raise ValueError("April15 replay differs from pinned 419 misses")
    if sum(aggregate.values()) != sum(counted.values()):
        raise ValueError("Replay support mismatch")
    return {
        "status": "EXPOSED_APR15_17_AGGREGATE_ATTACK_MISS_DIAGNOSTICS_ONLY",
        "model_sha256": locked.MODEL_SHA,
        "model_cutoff": locked.CUTOFF,
        "source_sha256": locked.TARGET_SHA,
        "sample_replayed_exactly": True,
        "scanned_rows": stats["scanned"],
        "support_by_day": dict(sorted(counted.items())),
        "immutable_cutoff_confusion": dict(aggregate),
        "cutoff_sensitivity_exposed_not_holdout": {
            str(k): locked.summarize_confusion(v)
            for k, v in sorted(cutoff_counts.items())
        },
        "aggregate_categorical_breakdown": publish_slices(slices),
        "labels": "UNREVIEWED_PRODUCER_LABELS",
        "new_holdout": False,
        "candidate_retrained_or_tuned": False,
        "operational_ml_p0": "NO_GO",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    if args.report.exists() or args.report.is_symlink():
        parser.error("Refusing to overwrite evidence")
    report = run(args.archive, args.model)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.report, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as dest:
        json.dump(report, dest, indent=2, sort_keys=True, allow_nan=False)
        dest.write("\n")
    print(json.dumps({"status": report["status"],
                      "confusion": report["immutable_cutoff_confusion"],
                      "operational_ml_p0": "NO_GO"}))


if __name__ == "__main__":
    main()
