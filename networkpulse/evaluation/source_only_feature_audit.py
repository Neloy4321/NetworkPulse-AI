"""Reproducible source-only native feature contract audit and research baseline.

Only the approved authentic UNSW ZIP is accepted. No TON, CIC, deployed model,
or previously exposed external holdout participates in selection or fitting.
No flow record, address, identifier, or raw ZIP is written to the report.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import random
import re
import zipfile
from collections import Counter
from pathlib import Path

import numpy as np
import sklearn

from networkpulse.detector import train
from networkpulse.evaluation.live_unsw import read_reservoir
from networkpulse.evaluation.unsw_to_toniot import UNSW_SHA, digest, metrics, unique
from networkpulse.features import FEATURE_VERSION, event_features

SOURCE_MEMBER = "UNSW-NB15_1.csv"
SOURCE_EXPECTED_BYTES = 586382286
SAMPLE_CAP = 12000
SAMPLE_SEED = 42
TRAIN_QUANTILE = 0.995
SOURCE_FIT_FRACTION = 0.75
_MIN_FIT = 1000
_MIN_DEV = 400
_NUMERIC = (
    "log_duration", "log_orig_bytes", "log_resp_bytes",
    "log_orig_pkts", "log_resp_pkts", "log_bytes_per_second",
    "log_bytes_per_packet", "response_fraction", "dst_port",
    "dst_is_well_known",
)
_SAFE_STATE = re.compile(r"[a-z0-9_-]{1,24}\Z")


def source_only_chronological_split(events):
    """Deduplicate canonical identities/fingerprints then group equal timestamps.

    Strictly split before model fit: dev labels cannot influence feature choice,
    threshold fitting, sample selection, or hyperparameter selection.
    """
    if not events:
        raise ValueError("source-only sample is empty")
    for event in events:
        if event.source != "canonical" or event.label not in {"benign", "anomaly"}:
            raise ValueError("source-only evaluation requires authentic labeled canonical flows")
    deduped, excluded = unique(events)
    ordered = sorted(deduped, key=lambda item: (item.timestamp, item.key()))
    if len(ordered) < _MIN_FIT + _MIN_DEV:
        raise ValueError("insufficient unique source-only flows")
    cut = int(len(ordered) * SOURCE_FIT_FRACTION)
    if cut <= 0 or cut >= len(ordered):
        raise ValueError("cannot create chronological split")
    first_dev_time = ordered[cut].timestamp
    fit = [item for item in ordered if item.timestamp < first_dev_time]
    dev = [item for item in ordered if item.timestamp >= first_dev_time]
    if len(fit) < _MIN_FIT or len(dev) < _MIN_DEV:
        raise ValueError("source-only timestamp groups do not support safe fit/dev partition")
    if max(x.timestamp for x in fit) >= min(x.timestamp for x in dev):
        raise ValueError("chronological source-only split leaks equal timestamps")
    # The normalized fingerprint (which excludes labels/adapter IDs) protects
    # against fitting on the identical traffic later used for development metrics.
    if {x.key() for x in fit} & {x.key() for x in dev}:
        raise ValueError("source fit/dev canonical ID overlap")
    return fit, dev, excluded




def source_only_grouped_split(events):
    """Seeded host-pair/protocol-disjoint 75/25 *development* split.

    Grouping keys are used only in memory; network host identities never appear
    in artifacts. Groups are assigned independently of labels or model scores.
    This is NOT chronological or cross-site generalization evidence.
    """
    if not events:
        raise ValueError("source-only sample is empty")
    if any(e.source != "canonical" or e.label not in {"benign", "anomaly"} for e in events):
        raise ValueError("authentic labeled canonical source flows are required")
    unique_flows, excluded = unique(events)
    groups = {}
    for event in unique_flows:
        group = (str(event.src_ip), str(event.dst_ip), event.proto)
        groups.setdefault(group, []).append(event)
    keys = sorted(groups)
    if len(keys) < 8:
        raise ValueError("insufficient independent source host-pair groups")
    random.Random(SAMPLE_SEED).shuffle(keys)
    split = max(1, int(len(keys) * 0.25))
    dev_group_keys = set(keys[:split])
    fit, dev = [], []
    for key, rows in groups.items():
        (dev if key in dev_group_keys else fit).extend(rows)
    if len(fit) < _MIN_FIT or len(dev) < _MIN_DEV:
        raise ValueError("insufficient source-only group-disjoint populations")
    if {(str(e.src_ip), str(e.dst_ip), e.proto) for e in fit} & {
        (str(e.src_ip), str(e.dst_ip), e.proto) for e in dev
    }:
        raise ValueError("host-pair group overlap in source-only benchmark")
    return fit, dev, excluded, len(keys)


def source_only_grouped_baseline(events):
    """Unchanged v1 model, with host-pair-disjoint source-only dev groups."""
    try:
        fit, dev, removed, group_count = source_only_grouped_split(events)
    except ValueError as exc:
        return {
            "status": "blocked_insufficient_source_host_pair_groups",
            "reason": str(exc),
            "metrics": None,
        }
    dev_classes = Counter(e.label for e in dev)
    if dev_classes["benign"] < 100 or dev_classes["anomaly"] < 100:
        return {
            "status": "blocked_insufficient_grouped_dev_class_support",
            "dev_class_counts": {
                "benign": dev_classes["benign"], "anomaly": dev_classes["anomaly"]
            },
            "required_per_class": 100,
            "group_count": group_count,
            "metrics": None,
        }
    trained = train(
        fit, quantile=TRAIN_QUANTILE, seed=SAMPLE_SEED,
        source="UNSW_real_grouped_source_only_research_baseline",
    )
    result = metrics(dev, trained.score(dev))
    result.pop("operational_gate", None)
    return {
        "status": "source_only_grouped_development_measurement_not_acceptance",
        "method": "unchanged_native_isolation_forest_feature_v1",
        "fit_rows": len(fit),
        "dev_rows": len(dev),
        "dev_class_counts": {
            "benign": dev_classes["benign"], "anomaly": dev_classes["anomaly"]
        },
        "total_host_pair_protocol_groups": group_count,
        "duplicate_events_removed": removed,
        "host_pair_group_disjoint": True,
        "strict_timestamp_separation": False,
        "timestamp_overlap_allowed": True,
        "model_feature_version": trained.metadata["feature_version"],
        "threshold_source": "fit_only_internal_benign_calibration",
        "model_quantile": TRAIN_QUANTILE,
        "model_seed": SAMPLE_SEED,
        "test_labels_used_to_fit": False,
        "metrics": result,
        "interpretation": (
            "Same-source host-pair/protocol-disjoint development; groups do not "
            "prove independent networks, chronological validity or acceptance. "
            "NOT a holdout used to claim production performance."
        ),
    }

def _summary_numeric(values):
    data = np.asarray(values, dtype=float)
    if data.size == 0 or not np.isfinite(data).all():
        raise ValueError("feature contract audit received non-finite values")
    return {
        "min": round(float(np.min(data)), 6),
        "p25": round(float(np.quantile(data, 0.25)), 6),
        "median": round(float(np.median(data)), 6),
        "p75": round(float(np.quantile(data, 0.75)), 6),
        "max": round(float(np.max(data)), 6),
    }


def feature_contract_audit(events):
    """Aggregate model feature behavior; never serialize raw source records."""
    if not events:
        raise ValueError("at least one canonical event is needed")
    vectors = [event_features(event) for event in events]
    for values in vectors:
        if set(_NUMERIC) - set(values):
            raise ValueError("model feature contract is missing numeric coordinates")
        if sum(key.startswith("proto=") for key in values) != 1:
            raise ValueError("model feature contract must encode exactly one protocol")
        if sum(key.startswith("state=") for key in values) != 1:
            raise ValueError("model feature contract must encode exactly one connection state")
    numeric = {}
    for name in _NUMERIC:
        numeric[name] = _summary_numeric([float(x[name]) for x in vectors])
    proto_counts = Counter(event.proto for event in events)
    states = Counter(event.conn_state for event in events)
    safe_states = [
        {"state": key, "count": count}
        for key, count in sorted(states.items(), key=lambda item: (-item[1], item[0]))
        if _SAFE_STATE.fullmatch(key)
    ][:12]
    return {
        "feature_version": FEATURE_VERSION,
        "native_feature_count_numeric": len(_NUMERIC),
        "numeric_feature_summaries": numeric,
        "protocol_counts": {k: proto_counts[k] for k in sorted(proto_counts)},
        "distinct_connection_state_count": len(states),
        "top_connection_states": safe_states,
        "zero_duration_flows": sum(x.duration == 0 for x in events),
        "no_response_packet_flows": sum(x.resp_pkts == 0 for x in events),
        "high_destination_port_flows": sum(x.dst_port >= 49152 for x in events),
        "zero_byte_flows": sum(x.orig_bytes + x.resp_bytes == 0 for x in events),
        "warnings": [
            "UNSW 'state' and TON 'conn_state' are distinct sensor conventions; "
            "cross-sensor semantic equivalence is NOT established.",
            "The native model uses raw numeric destination port, which can imply "
            "unsupported ordinal distance; a bucketed feature is a proposal only.",
            "Bytes/sec uses max(0.01, duration) so zero-duration flow values "
            "require source-only semantics review before feature changes.",
            "No TON statistics, labels or performance used to propose candidate changes.",
        ],
    }


def source_only_baseline(events):
    fit, dev, removed = source_only_chronological_split(events)
    class_counts = Counter(event.label for event in dev)
    # This source's temporally late capture can contain almost one class.
    # Do NOT fabricate class balance or score a one-class dev set as a benchmark.
    if class_counts["benign"] < 100 or class_counts["anomaly"] < 100:
        return {
            "status": "blocked_insufficient_chronological_dev_class_support",
            "fit_rows": len(fit), "dev_rows": len(dev),
            "dev_class_counts": {
                "benign": class_counts["benign"],
                "anomaly": class_counts["anomaly"],
            },
            "required_per_class": 100,
            "duplicate_events_removed": removed,
            "strict_timestamp_separation": (
                max(x.timestamp for x in fit) < min(x.timestamp for x in dev)
            ),
            "metrics": None,
            "interpretation": (
                "No valid two-class source-only development benchmark; "
                "no acceptance metric, threshold tuning, resampling or leakage workaround."
            ),
        }
    # Predeclare a single unchanged model, its quantile, seed and feature contract.
    # The fit partition itself is internally split by train() for fit/calibration.
    trained = train(
        fit, quantile=TRAIN_QUANTILE, seed=SAMPLE_SEED,
        source="UNSW_real_source_only_research_baseline",
    )
    predictions = trained.score(dev)
    baseline_metrics = metrics(dev, predictions)
    # metrics() has an external-study gate diagnostic; explicitly strip its
    # "passed/failed" acceptance wording for a same-source development sample.
    baseline_metrics.pop("operational_gate", None)
    return {
        "status": "source_only_development_measurement_not_acceptance",
        "method": "unchanged_native_isolation_forest_feature_v1",
        "fit_rows": len(fit),
        "dev_rows": len(dev),
        "duplicate_events_removed": removed,
        "fit_last_day": max(x.timestamp for x in fit).date().isoformat(),
        "dev_first_day": min(x.timestamp for x in dev).date().isoformat(),
        "strict_timestamp_separation": (
            max(x.timestamp for x in fit) < min(x.timestamp for x in dev)
        ),
        "threshold_source": "fit_only_internal_benign_calibration",
        "test_labels_used_to_fit": False,
        "model_feature_version": trained.metadata["feature_version"],
        "trained_count": trained.metadata["train_count"],
        "calibrated_count": trained.metadata["cal_count"],
        "model_quantile": TRAIN_QUANTILE,
        "model_seed": SAMPLE_SEED,
        "metric_scope": "single_source_development_only",
        "metrics": baseline_metrics,
        "interpretation": (
            "Descriptive source-only benchmark, NOT cross-domain performance, "
            "untouched holdout, production sign-off or independent-site acceptance."
        ),
    }


def run(path: Path, *, cap: int = SAMPLE_CAP) -> dict:
    if cap != SAMPLE_CAP:
        raise ValueError("sample cap is fixed for reproducible predeclared Stage 1 baseline")
    if path.stat().st_size != SOURCE_EXPECTED_BYTES or digest(path) != UNSW_SHA:
        raise ValueError("refusing non-pinned UNSW source archive")
    with zipfile.ZipFile(path) as archive:
        sample, scan_info = read_reservoir(archive, SOURCE_MEMBER, cap, SAMPLE_SEED)
    if digest(path) != UNSW_SHA:
        raise ValueError("source archive changed during feature audit")
    audit = feature_contract_audit(sample)
    benchmark = source_only_baseline(sample)
    grouped = source_only_grouped_baseline(sample)
    params = {
        "source_zip_sha256": UNSW_SHA,
        "source_member": SOURCE_MEMBER,
        "sample_cap": SAMPLE_CAP,
        "sample_seed": SAMPLE_SEED,
        "source_fit_fraction": SOURCE_FIT_FRACTION,
        "calibration_quantile": TRAIN_QUANTILE,
        "feature_version": FEATURE_VERSION,
        "baseline": "native_isolation_forest_unmodified",
    }
    param_sha = hashlib.sha256(
        json.dumps(params, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": 1,
        "status": "source_only_feature_audit_completed",
        "research_only": True,
        "operational_acceptance_demonstrated": False,
        "source": "UNSW-NB15 authorized raw archive; earlier capture only",
        "protocol": params,
        "protocol_sha256": param_sha,
        "dependency_versions": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "archive_scan": scan_info,
        "feature_contract_audit": audit,
        "source_only_baseline": benchmark,
        "source_only_grouped_baseline": grouped,
        "limitations": [
            "Source-only chronology is not independent physical-site generalization.",
            "Reservoir sampling can alter natural prevalence and capture coverage.",
            "Wilson uncertainty assumes independent flows and is optimistic for correlated traffic.",
            "Native feature contract is unchanged; proposed v2 changes are not validated.",
            "Group-disjoint development is within one source capture, not a new site.",
            "The source-only sample has not been used to pick a production model.",
            "No previously inspected TON target outcomes influenced this benchmark.",
            "Version reporting supports replication but packages are not fully locked.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unsw-zip", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite existing research evidence")
    report = run(args.unsw_zip)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")
    print(json.dumps({
        "status": report["status"],
        "sample": report["archive_scan"]["selected_before_dedup"],
        "fit": report["source_only_baseline"]["fit_rows"],
        "development": report["source_only_baseline"]["dev_rows"],
        "benchmark_status": report["source_only_baseline"]["status"],
        "chronological_development_fpr": (
            report["source_only_baseline"]["metrics"]["fpr"]
            if report["source_only_baseline"]["metrics"] is not None else None
        ),
        "grouped_benchmark_status": report["source_only_grouped_baseline"]["status"],
        "grouped_development_fpr": (
            report["source_only_grouped_baseline"]["metrics"]["fpr"]
            if report["source_only_grouped_baseline"]["metrics"] is not None else None
        ),
        "operational_acceptance_demonstrated": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
