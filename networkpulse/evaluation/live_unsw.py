"""Evaluate the actual NetworkPulse Detector/feature pipeline on real UNSW raw flows.

This does not overwrite or promote the local production/demo artifact.
Training uses earlier capture only; later capture test labels never fit a model.
Only aggregates, never IP addresses or raw flows, reach output.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import random
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.metrics import (average_precision_score, confusion_matrix,
                             precision_recall_fscore_support, roc_auc_score)

from networkpulse.detector import train
from networkpulse.schemas import FlowEvent
from networkpulse.simulator import sample_flows
from networkpulse.evaluation.unsw import _hash_file
from tools.real_data_benchmark import UNSW_COLUMNS


def raw_unsw_to_event(row: dict[str, str]) -> FlowEvent:
    r = {str(k).lower(): (v or "").strip() for k, v in row.items()}
    def num(field, *, integral=False):
        try:
            value = float(r[field])
        except (ValueError, KeyError, TypeError) as e:
            raise ValueError("invalid numeric field: " + field) from e
        if not math.isfinite(value) or value < 0 or (integral and not value.is_integer()):
            raise ValueError("invalid field: " + field)
        return int(value) if integral else value
    label = r["label"]
    if label not in {"0", "1"}:
        raise ValueError("invalid label")
    proto = r["proto"].lower()
    if proto not in {"tcp", "udp", "icmp"}:
        proto = "other"
    return FlowEvent(
        timestamp=datetime.fromtimestamp(num("stime"), tz=timezone.utc),
        source="canonical",
        src_ip=r["srcip"], dst_ip=r["dstip"],
        src_port=num("sport", integral=True),
        dst_port=num("dsport", integral=True),
        proto=proto, duration=num("dur"),
        orig_bytes=num("sbytes", integral=True),
        resp_bytes=num("dbytes", integral=True),
        orig_pkts=num("spkts", integral=True),
        resp_pkts=num("dpkts", integral=True),
        conn_state=r["state"][:24] or "unknown",
        label="anomaly" if label == "1" else "benign",
    )


def read_reservoir(zf: zipfile.ZipFile, name: str, limit: int, seed: int):
    rand = random.Random(seed)
    rows = []
    counters = Counter()
    labels = Counter()
    with zf.open(name) as f:
        reader = csv.DictReader(
            io.TextIOWrapper(f, encoding="utf-8-sig", errors="replace", newline=""),
            fieldnames=UNSW_COLUMNS,
        )
        for row in reader:
            try:
                event = raw_unsw_to_event(row)
            except (ValueError, KeyError, OverflowError, TypeError):
                counters["rejected"] += 1
                continue
            counters["valid"] += 1
            labels[event.label] += 1
            if len(rows) < limit:
                rows.append(event)
            else:
                index = rand.randrange(counters["valid"])
                if index < limit:
                    rows[index] = event
    return rows, {"valid_rows": counters["valid"], "invalid_rows": counters["rejected"],
                  "label_counts_full_scan": dict(labels), "selected_before_dedup": len(rows),
                  "source_file": name}


def evaluate_scores(events: list[FlowEvent], detections) -> dict:
    y = np.asarray([int(e.label == "anomaly") for e in events])
    pred = np.asarray([int(d.anomalous) for d in detections])
    scores = np.asarray([d.anomaly_score for d in detections])
    p, recall, f1, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"precision": round(float(p), 5), "recall": round(float(recall), 5),
            "f1": round(float(f1), 5),
            "false_positive_rate": round(float(fp / max(1, tn+fp)), 5),
            "alerts": int(pred.sum()),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
            "roc_auc": round(float(roc_auc_score(y, scores)), 5) if len(set(y)) > 1 else None,
            "pr_auc": round(float(average_precision_score(y, scores)), 5) if len(set(y)) > 1 else None}


def run(path: Path, *, seed=42, max_train=2200, max_test=1300) -> dict:
    with zipfile.ZipFile(path) as zf:
        a, train_info = read_reservoir(zf, "UNSW-NB15_1.csv", max_train, seed)
        b, test_info = read_reservoir(zf, "UNSW-NB15_4.csv", max_test, seed + 1)
    # Deduplicate event identity, not feature-only: distinct sessions are
    # separate legitimate flows; feature collisions alone aren't sufficient.
    train_map = {e.key(): e for e in a}
    test_map = {e.key(): e for e in b}
    for key in train_map:
        test_map.pop(key, None)
    train_events, test_events = list(train_map.values()), list(test_map.values())
    if len(train_events) < 100 or len(test_events) < 100:
        raise ValueError("insufficient independent source rows")
    low_train = min(e.timestamp for e in train_events)
    high_train = max(e.timestamp for e in train_events)
    low_test = min(e.timestamp for e in test_events)
    if high_train >= low_test:
        raise ValueError("capture times overlap")
    if len({e.label for e in test_events}) < 2:
        raise ValueError("test needs benign and anomalies")
    # This is the actual Detector code used by API/worker scoring, trained
    # only from the earlier real capture, not the separately fitted benchmarks.
    trained = train(train_events, seed=seed, source="unsw_raw_real_capture")
    evaluated = trained.score(test_events)
    # Reference: the shipped synthetic-first training regime applied to the
    # exact same independent real test flows. Never promote either artifact.
    demo = train(sample_flows(1300, seed=seed), seed=seed, source="synthetic_reference")
    demo_eval = demo.score(test_events)
    return {
        "evaluation": "NetworkPulse native Detector + feature pipeline",
        "source": "UNSW-NB15 raw 49-column headerless CSV",
        "source_archive_sha256": _hash_file(path),
        "seed": seed, "sample_caps": {"train": max_train, "test": max_test},
        "train_source": train_info, "test_source": test_info,
        "data_partition": {
            "train_timestamp_min": low_train.isoformat(),
            "train_timestamp_max": high_train.isoformat(),
            "test_timestamp_min": low_test.isoformat(),
            "test_later_than_train": True, "site_independence_verified": False,
        },
        "sample_counts": {
            "train_unique_events": len(train_events),
            "test_unique_events": len(test_events),
            "test_attacks": sum(e.label == "anomaly" for e in test_events),
            "exact_duplicates_removed_train": len(a) - len(train_events),
            "exact_duplicates_removed_test": len(b) - len(test_events),
        },
        "real_capture_trained_native_detector": {
            "model_feature_count": trained.metadata["feature_count"],
            "train_count": trained.metadata["train_count"],
            "calibration_count": trained.metadata["cal_count"],
            "threshold": trained.threshold,
            "heldout_capture_metrics": evaluate_scores(test_events, evaluated),
        },
        "synthetic_trained_native_detector_real_test": {
            "model_feature_count": demo.metadata["feature_count"],
            "threshold": demo.threshold,
            "heldout_capture_metrics": evaluate_scores(test_events, demo_eval),
        },
        "notes": [
            "No source/target IP, UID or source label is an input model feature.",
            "Native Detector training internally uses chronological 60/15/25 split of earlier capture.",
            "Original raw UNSW row labels are not used for unsupervised fitting except benign inclusion.",
            "Later capture labels used only for final metrics, never model fitting or calibration.",
            "Original production model artifact is not modified; synthetic reference retrained reproducibly.",
            "Same original UNSW cyber range may include overlapping hosts; unseen-site validation unverified.",
        ],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--max-train", type=int, default=2200)
    ap.add_argument("--max-test", type=int, default=1300)
    args = ap.parse_args()
    result = run(args.zip, max_train=args.max_train, max_test=args.max_test)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({
        "evaluation": result["evaluation"],
        "data_partition": result["data_partition"],
        "sample_counts": result["sample_counts"],
        "model_results": {
            "real_capture_native": result["real_capture_trained_native_detector"]["heldout_capture_metrics"],
            "synthetic_reference_native": result["synthetic_trained_native_detector_real_test"]["heldout_capture_metrics"],
        },
    }, indent=2))


if __name__ == "__main__":
    main()
