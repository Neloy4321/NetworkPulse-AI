"""Post-fit source-independent OR stress: UWF Zeek producer-labelled sample.

Model and cutoffs are fit/selected solely on source IoT-SFC before this code
reads UWF labels. UWF source has already been inspected in the historical
frozen-model diagnostic, so even successful OR metrics are exploratory only.
This is a different university cyber-range, not a certified IoT field site.
"""
from __future__ import annotations

import csv
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from networkpulse.evaluation import iot_sfc_locked_later_days as locked
from networkpulse.evaluation import iot_sfc_mqtt_repair as repair
from networkpulse.evaluation.iot_sfc_frozen_score import digest
from networkpulse.feature_contract_v2 import features_v2, from_zeek_v2

SHA = "991d7cd72f299484ab2892df21a02cd838fea0dce3e92eab6a406c69f78e79c2"
RAW_ROWS = 10_490
HEADER = (
    "resp_pkts", "service", "orig_ip_bytes", "local_resp", "missed_bytes",
    "protocol", "duration", "conn_state", "dest_ip", "orig_pkts",
    "community_id", "resp_ip_bytes", "dest_port", "orig_bytes",
    "local_orig", "datetime", "history", "resp_bytes", "uid", "src_port",
    "ts", "src_ip", "mitre_attack_tactics",
)


def adapt_record(row):
    return from_zeek_v2({
        "ts": row["ts"], "uid": row["uid"],
        "id.orig_h": row["src_ip"], "id.resp_h": row["dest_ip"],
        "id.orig_p": row["src_port"], "id.resp_p": row["dest_port"],
        "proto": row["protocol"], "duration": row["duration"],
        "orig_bytes": row["orig_bytes"], "resp_bytes": row["resp_bytes"],
        "orig_pkts": row["orig_pkts"], "resp_pkts": row["resp_pkts"],
        "conn_state": row["conn_state"],
    })


def read_label(text: str) -> int:
    if text == "none":
        return 0
    if text == "Discovery":
        return 1
    raise ValueError("Unrecognized external source MITRE tactic")


def score(csv_file: Path, frozen: dict, encoder, repair_model, cutoff: float) -> dict:
    if digest(csv_file) != SHA:
        raise ValueError("Independent source immutable file mismatch")
    old_counts = Counter()
    new_counts = Counter()
    or_counts = Counter()
    day_support = defaultdict(Counter)
    or_days = defaultdict(Counter)
    stats = Counter()
    seen = set()
    flows, ys, days = [], [], []

    def flush():
        if not flows:
            return
        original_prob = frozen["estimator"].predict_proba(
            frozen["vectorizer"].transform([features_v2(f) for f in flows])
        )
        repair_prob = repair_model.predict_proba(
            encoder.transform([repair.features_repair(f) for f in flows])
        )
        if (original_prob.shape != (len(flows), 2)
                or repair_prob.shape != (len(flows), 2)
                or not np.isfinite(original_prob).all()
                or not np.isfinite(repair_prob).all()):
            raise ValueError("Cross-source candidate prediction shape or NaN")
        for old, current, y, day in zip(original_prob[:, 1], repair_prob[:, 1],
                                        ys, days):
            old_pos = old >= locked.CUTOFF
            new_pos = current >= cutoff
            or_pos = repair.frozen_or_repair(old, current, cutoff)
            for bucket, pos in ((old_counts, old_pos), (new_counts, new_pos),
                                (or_counts, or_pos), (or_days[day], or_pos)):
                bucket[("tp" if y else "fp") if pos else ("fn" if y else "tn")] += 1
        flows.clear()
        ys.clear()
        days.clear()

    with csv_file.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle, restkey="__extra__", restval=None)
        if tuple(reader.fieldnames or ()) != HEADER:
            raise ValueError("Independent Zeek CSV header changed")
        for row in reader:
            stats["raw_rows"] += 1
            if row.get("__extra__") is not None or any(v is None for v in row.values()):
                raise ValueError("Unexpected external CSV record structure")
            y = read_label(row["mitre_attack_tactics"])
            stats["raw_attack" if y else "raw_benign"] += 1
            flow = adapt_record(row)
            identity = (flow.uid, flow.timestamp, str(flow.src_ip), str(flow.dst_ip),
                        flow.src_port, flow.dst_port, flow.proto)
            if identity in seen:
                stats["duplicate_flow"] += 1
                continue
            seen.add(identity)
            day = flow.timestamp.date().isoformat()
            day_support[day]["attack" if y else "benign"] += 1
            flows.append(flow)
            ys.append(y)
            days.append(day)
            if len(flows) >= locked.BATCH_SIZE:
                flush()
    flush()
    if (stats["raw_rows"] != RAW_ROWS or stats["raw_attack"] != 2086
            or stats["raw_benign"] != 8404 or stats["duplicate_flow"] != 13
            or sum(old_counts.values()) != 10477
            or sum(new_counts.values()) != sum(old_counts.values())
            or sum(or_counts.values()) != sum(old_counts.values())):
        raise ValueError("Cross-source sample/score support changed")
    # Independent, previously obtained fixed-frozen external diagnostic must
    # replay exactly. This checks adapter parity, never tunes a threshold.
    if dict(old_counts) != {"tn": 8376, "fp": 15, "fn": 1714, "tp": 372}:
        raise ValueError("Frozen UWF cross-source result did not reproduce")
    if or_counts["fn"] > old_counts["fn"]:
        raise ValueError("OR rule unexpectedly discarded frozen positives")
    mixed_days = sum(bool(d["benign"] and d["attack"])
                     for d in day_support.values())
    return {
        "status": "POST_LOCK_FROZEN_OR_MQTT_UWF_ALREADY_INSPECTED_RESEARCH",
        "external_source_sha256": SHA,
        "original_source_model_sha256": locked.MODEL_SHA,
        "source_only_cutoff": cutoff,
        "frozen_cutoff": locked.CUTOFF,
        "source_raw_rows": stats["raw_rows"],
        "excluded_exact_duplicate_flows": stats["duplicate_flow"],
        "unique_flows": len(seen),
        "independent_university_source": True,
        "prospective_independent_field_site": False,
        "external_labels_previously_exposed_in_frozen_diagnostic": True,
        "producer_label_truth_independently_adjudicated": False,
        "external_test_used_for_fit_or_cutoff_choice": False,
        "dates_with_benign_and_attack": mixed_days,
        "source_label_date_confounding": mixed_days == 0,
        "frozen": locked.summarize_confusion(old_counts),
        "repair": locked.summarize_confusion(new_counts),
        "frozen_or_repair": locked.summarize_confusion(or_counts),
        "or_by_day": {day: locked.summarize_confusion(c)
                      for day, c in sorted(or_days.items())},
        "model_exported_or_deployed": False,
        "operational_ml_p0": "NO_GO",
    }
