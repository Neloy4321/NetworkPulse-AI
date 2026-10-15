"""Post-hoc, aggregate-only native Detector domain-shift diagnostics.

This diagnostic inspects an ALREADY-EXPOSED target capture. It MUST NOT select
features, thresholds, models or hyperparameters for a claimed independent test.
No flow identifiers, IP addresses, raw rows or host-specific slices are emitted.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict

import numpy as np

from networkpulse.features import event_features
from networkpulse.generalization_evidence import wilson_interval

NUMERIC_FEATURES = (
    "log_duration",
    "log_orig_bytes",
    "log_resp_bytes",
    "log_orig_pkts",
    "log_resp_pkts",
    "log_bytes_per_second",
    "log_bytes_per_packet",
    "response_fraction",
    "dst_port",
    "dst_is_well_known",
)
MIN_SLICE_BENIGN = 30
MIN_SLICE_ATTACK = 30


def _summary(values: list[float]) -> dict:
    data = np.asarray(values, dtype=float)
    if not len(data) or not np.all(np.isfinite(data)):
        raise ValueError("Diagnostics require finite numeric observations")
    return {
        "n": len(values),
        "p25": round(float(np.quantile(data, .25)), 6),
        "median": round(float(np.median(data)), 6),
        "p75": round(float(np.quantile(data, .75)), 6),
    }


def feature_shift(source, target) -> dict:
    """Benign-to-benign post-hoc shift; no labels fed back into model fitting."""
    source_benign = [event for event in source if event.label == "benign"]
    target_benign = [event for event in target if event.label == "benign"]
    if len(source_benign) < 30 or len(target_benign) < 30:
        raise ValueError("At least 30 authentic benign source/target events required")

    source_rows = [event_features(e) for e in source_benign]
    target_rows = [event_features(e) for e in target_benign]
    differences = {}
    for name in NUMERIC_FEATURES:
        source_dist = _summary([float(row[name]) for row in source_rows])
        target_dist = _summary([float(row[name]) for row in target_rows])
        # Diagnostic scale, not a test statistic or significance claim.
        denominator = max(source_dist["p75"] - source_dist["p25"], .01)
        differences[name] = {
            "source": source_dist,
            "target": target_dist,
            "median_shift_in_source_iqr_units": round(
                (target_dist["median"] - source_dist["median"]) / denominator, 4
            ),
        }
    return {
        "status": "posthoc_exploratory_only",
        "comparison": "sampled_benign_source_vs_already_inspected_target_benign",
        "source_benign": len(source_benign),
        "target_benign": len(target_benign),
        "numeric_feature_summaries": differences,
        "warning": (
            "Target labels and distributions were already inspected. Do not use "
            "these values for model, feature or threshold selection; this is not "
            "an independent acceptance test or causal attribution."
        ),
    }


def _group_metrics(records: list[tuple[bool, bool]], label: str) -> dict:
    counts = Counter()
    for is_attack, is_alert in records:
        counts[("tp" if is_alert else "fn") if is_attack else
               ("fp" if is_alert else "tn")] += 1
    benign = counts["tn"] + counts["fp"]
    attacks = counts["tp"] + counts["fn"]
    result = {
        "group": label, "benign": benign, "attack": attacks,
        "confusion_matrix": {k: counts[k] for k in ("tn", "fp", "fn", "tp")},
        "fpr": None, "fpr_wilson95": None,
        "recall": None, "recall_wilson95": None,
    }
    if benign >= MIN_SLICE_BENIGN:
        result["fpr"] = round(counts["fp"] / benign, 6)
        result["fpr_wilson95"] = [
            round(float(value), 6) for value in wilson_interval(counts["fp"], benign)
        ]
    if attacks >= MIN_SLICE_ATTACK:
        result["recall"] = round(counts["tp"] / attacks, 6)
        result["recall_wilson95"] = [
            round(float(value), 6) for value in wilson_interval(counts["tp"], attacks)
        ]
    return result


def alert_slices(target, detections) -> dict:
    """Suppress low-support groups; no IP, UID or attacker-supplied rare state output."""
    if len(target) != len(detections) or not target:
        raise ValueError("A prediction is required for every target observation")
    by_protocol = defaultdict(list)
    by_state = defaultdict(list)
    for event, detection in zip(target, detections):
        if event.label not in {"benign", "anomaly"}:
            raise ValueError("Unlabeled target row in diagnostic")
        if type(detection.anomalous) is not bool or not math.isfinite(
            float(detection.anomaly_score)
        ):
            raise ValueError("Invalid native detector prediction")
        record = (event.label == "anomaly", detection.anomalous)
        by_protocol[event.proto].append(record)
        by_state[event.conn_state].append(record)

    def report(groups):
        return [
            _group_metrics(rows, group) for group, rows in sorted(groups.items())
            if sum(not attack for attack, _ in rows) >= MIN_SLICE_BENIGN
            or sum(attack for attack, _ in rows) >= MIN_SLICE_ATTACK
        ]

    return {
        "status": "posthoc_diagnostic_not_acceptance",
        "minimum_benign_for_fpr": MIN_SLICE_BENIGN,
        "minimum_attack_for_recall": MIN_SLICE_ATTACK,
        "by_protocol": report(by_protocol),
        "by_connection_state": report(by_state),
        "suppressed_small_groups": {
            "protocol": len(by_protocol) - len(report(by_protocol)),
            "connection_state": len(by_state) - len(report(by_state)),
        },
        "warning": (
            "Flow-level intervals ignore clustered sessions/hosts. Post-hoc "
            "breakdowns from already-inspected target must never drive candidate "
            "selection and do not demonstrate field production acceptance."
        ),
    }
