"""P0 cross-source external research stress with unchanged historical model.

UWF-ZeekData22 is an independent university cyber-range source, NOT an
independent IoT field deployment. This fixed CSV sample includes Discovery
and benign producer labels on disjoint calendar periods, so no operational
per-day ML acceptance is possible from it. Never train, tune or export here.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
from collections import Counter, defaultdict
from pathlib import Path

import joblib
import numpy as np
import sklearn

from networkpulse.evaluation import iot_sfc_locked_later_days as locked
from networkpulse.evaluation.iot_sfc_frozen_score import digest
from networkpulse.feature_contract_v2 import FlowV2, features_v2, from_zeek_v2

SAMPLE_URL = (
    "https://datasets.uwf.edu/data/UWF-ZeekData22/csv/"
    "part-00000-15e3dd03-ea76-429e-a52a-ce96a90517f9-c000.csv"
)
SAMPLE_SHA256 = "991d7cd72f299484ab2892df21a02cd838fea0dce3e92eab6a406c69f78e79c2"
EXPECTED_RAW_ROWS = 10_490
EXPECTED_RAW_BENIGN = 8_404
EXPECTED_RAW_ATTACK = 2_086
HEADER = (
    "resp_pkts", "service", "orig_ip_bytes", "local_resp", "missed_bytes",
    "protocol", "duration", "conn_state", "dest_ip", "orig_pkts",
    "community_id", "resp_ip_bytes", "dest_port", "orig_bytes",
    "local_orig", "datetime", "history", "resp_bytes", "uid", "src_port",
    "ts", "src_ip", "mitre_attack_tactics",
)
BATCH_SIZE = 2048


def producer_label(value: str) -> int:
    if value == "none":
        return 0
    if value == "Discovery":
        return 1
    raise ValueError("Unexpected external source-provided tactic label")


def adapt_uwf_zeek(row: dict) -> FlowV2:
    """Map only sensor fields, never mitigation tactics or record identities."""
    zeek = {
        "ts": row["ts"], "uid": row["uid"],
        "id.orig_h": row["src_ip"], "id.resp_h": row["dest_ip"],
        "id.orig_p": row["src_port"], "id.resp_p": row["dest_port"],
        "proto": row["protocol"], "duration": row["duration"],
        "orig_bytes": row["orig_bytes"], "resp_bytes": row["resp_bytes"],
        "orig_pkts": row["orig_pkts"], "resp_pkts": row["resp_pkts"],
        "conn_state": row["conn_state"],
    }
    return from_zeek_v2(zeek)


def load_pinned_original(model_path: Path):
    """Deserialize only the exact previously SHA-verified research artifact."""
    if digest(model_path) != locked.MODEL_SHA or sklearn.__version__ != "1.9.1":
        raise ValueError("Frozen research model hash or runtime mismatch")
    candidate = joblib.load(model_path)
    if (candidate.get("schema_version") != 2
            or candidate.get("research_only") is not True
            or candidate.get("production_approved") is not False
            or candidate.get("dataset_sha256") != locked.TARGET_SHA
            or candidate.get("candidate") != "extra_trees"
            or candidate.get("cutoff") != locked.CUTOFF
            or candidate.get("feature_contract") != "missingness_aware_flow_v2"
            or candidate.get("training_dates") != "through_2025-04-08"
            or candidate.get("source_dev_date") != "2025-04-10"
            or candidate.get("heldout_test_dates_not_used_in_fit_or_selection")
            != "2025-04-12_2025-04-17"
            or candidate.get("scikit_learn_version") != sklearn.__version__):
        raise ValueError("Pinned candidate protocol mismatch")
    return candidate


def score_external(csv_path: Path, model_path: Path) -> dict:
    if digest(csv_path) != SAMPLE_SHA256:
        raise ValueError("Independent source sample SHA mismatch")
    model = load_pinned_original(model_path)
    totals = Counter()
    by_day = defaultdict(Counter)
    by_day_support = defaultdict(Counter)
    seen = set()
    flows, labels, dates = [], [], []

    def flush() -> None:
        if not flows:
            return
        vector = model["vectorizer"].transform([features_v2(f) for f in flows])
        probabilities = model["estimator"].predict_proba(vector)
        if probabilities.shape != (len(flows), 2) or not np.isfinite(probabilities).all():
            raise ValueError("Invalid pinned candidate scores")
        for prob, truth, day in zip(probabilities[:, 1], labels, dates):
            positive = bool(prob >= locked.CUTOFF)
            cell = ("tp" if truth else "fp") if positive else (
                "fn" if truth else "tn"
            )
            totals[cell] += 1
            by_day[day][cell] += 1
        flows.clear()
        labels.clear()
        dates.clear()

    with csv_path.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source, restkey="__extra__", restval=None)
        if tuple(reader.fieldnames or ()) != HEADER:
            raise ValueError("External source Zeek CSV header mismatch")
        for row in reader:
            totals["raw_rows"] += 1
            if row.get("__extra__") is not None or any(v is None for v in row.values()):
                raise ValueError("Malformed external row width")
            truth = producer_label(row["mitre_attack_tactics"])
            totals["raw_attack" if truth else "raw_benign"] += 1
            flow = adapt_uwf_zeek(row)
            identity = (flow.uid, flow.timestamp, str(flow.src_ip), str(flow.dst_ip),
                        flow.src_port, flow.dst_port, flow.proto)
            if identity in seen:
                totals["duplicate_ignored"] += 1
                continue
            seen.add(identity)
            day = flow.timestamp.date().isoformat()
            by_day_support[day]["attack" if truth else "benign"] += 1
            flows.append(flow)
            labels.append(truth)
            dates.append(day)
            if len(flows) >= BATCH_SIZE:
                flush()
    flush()
    if (totals["raw_rows"] != EXPECTED_RAW_ROWS
            or totals["raw_benign"] != EXPECTED_RAW_BENIGN
            or totals["raw_attack"] != EXPECTED_RAW_ATTACK
            or totals["duplicate_ignored"] != 13):
        raise ValueError("External source sample support changed")
    if sum(totals[k] for k in ("tn", "fp", "fn", "tp")) != len(seen):
        raise ValueError("External unique flow accounting mismatch")
    mixed_days = [day for day, counts in by_day_support.items()
                  if counts["attack"] > 0 and counts["benign"] > 0]
    return {
        "status": "INDEPENDENT_UNIVERSITY_ZEEK_SOURCE_RESEARCH_ONLY",
        "external_source": SAMPLE_URL, "external_sha256": SAMPLE_SHA256,
        "frozen_model_sha256": locked.MODEL_SHA,
        "fixed_cutoff": locked.CUTOFF, "source_label_truth_independently_verified": False,
        "trained_or_selected_on_external_source": False,
        "model_exported_or_deployed": False,
        "raw_source_rows": totals["raw_rows"],
        "duplicate_flow_rows_not_scored": totals["duplicate_ignored"],
        "unique_scored_flows": len(seen),
        "producer_label_counts": {"benign": totals["raw_benign"],
                                  "Discovery": totals["raw_attack"]},
        "source_class_mixed_days": len(mixed_days),
        "source_label_date_confounding": len(mixed_days) == 0,
        "combined": locked.summarize_confusion(totals),
        "by_utc_day": {day: locked.summarize_confusion(cm)
                       for day, cm in sorted(by_day.items())},
        "operational_ml_p0": "NO_GO",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists() or args.report.is_symlink():
        parser.error("Refuse to overwrite existing evaluation evidence")
    result = score_external(args.csv, args.model)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.report, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as dest:
        json.dump(result, dest, sort_keys=True, indent=2, allow_nan=False)
        dest.write("\n")
    print(json.dumps({"scored": result["unique_scored_flows"],
                      "metrics": result["combined"],
                      "operational_ml_p0": "NO_GO"}))


if __name__ == "__main__":
    main()
