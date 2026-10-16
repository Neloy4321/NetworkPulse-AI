"""Predeclared supervised SOURCE-ONLY research candidates, not deployment models.

Uses only genuine UNSW source-fit labels; a fixed group-disjoint development
split is scored once. No TON, CIC, external holdout, tuning, model promotion
or raw flow records. These classifiers are NOT NetworkPulse Detector objects.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import zipfile
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer

from networkpulse.evaluation.live_unsw import read_reservoir
from networkpulse.evaluation.source_only_feature_audit import (
    SAMPLE_CAP, SAMPLE_SEED, SOURCE_EXPECTED_BYTES, SOURCE_MEMBER,
    source_only_grouped_split,
)
from networkpulse.evaluation.unsw_to_toniot import UNSW_SHA, digest, metrics
from networkpulse.features import FEATURE_VERSION, event_features

ESTIMATOR = {
    "n_estimators": 160,
    "max_depth": 12,
    "min_samples_leaf": 10,
    "class_weight": "balanced_subsample",
    "random_state": SAMPLE_SEED,
    "n_jobs": 1,
}
FIXED_CUTOFF = 0.5
MIN_PER_CLASS = 100
CANDIDATES = ("rf_supervised_v1", "rf_supervised_port_buckets_no_state")


def candidate_features(event, candidate: str) -> dict:
    if candidate not in CANDIDATES:
        raise ValueError("unknown or unregistered candidate feature contract")
    result = dict(event_features(event))
    if candidate == "rf_supervised_port_buckets_no_state":
        result.pop("dst_port")
        result.pop("dst_is_well_known")
        for key in tuple(result):
            if key.startswith("state="):
                del result[key]
        port = event.dst_port
        category = ("well_known" if port < 1024 else
                    "registered" if port < 49152 else "dynamic")
        result[f"port_class={category}"] = 1.0
    if "label" in result or any(
        key in result for key in ("timestamp", "src_ip", "dst_ip", "uid")
    ):
        raise ValueError("prohibited label/identifier feature")
    return result


def fit_and_evaluate(fit, dev, *, candidate: str) -> dict:
    """Fit only source FIT labels; read DEV labels exclusively for metrics."""
    if candidate not in CANDIDATES:
        raise ValueError("unregistered research candidate")
    training = Counter(event.label for event in fit)
    development = Counter(event.label for event in dev)
    if any(training[label] < MIN_PER_CLASS or development[label] < MIN_PER_CLASS
           for label in ("benign", "anomaly")):
        raise ValueError("each source-only group partition needs >=100 per class")
    # Stronger than row de-dup: block any shared host-pair/protocol group.
    group = lambda e: (str(e.src_ip), str(e.dst_ip), e.proto)
    if {group(e) for e in fit} & {group(e) for e in dev}:
        raise ValueError("source-fit/dev host-pair/protocol group overlap")
    fit_keys = {e.key() for e in fit}
    if fit_keys & {e.key() for e in dev}:
        raise ValueError("source-fit/dev event overlap")

    vectorizer = DictVectorizer(sparse=False)
    x_fit = vectorizer.fit_transform([candidate_features(e, candidate) for e in fit])
    y_fit = np.asarray([int(e.label == "anomaly") for e in fit], dtype=int)
    x_dev = vectorizer.transform([candidate_features(e, candidate) for e in dev])
    model = RandomForestClassifier(**ESTIMATOR)
    model.fit(x_fit, y_fit)
    if tuple(model.classes_) != (0, 1):
        raise ValueError("source-fit supervised classes are incomplete")
    scores = model.predict_proba(x_dev)[:, 1]
    if not np.isfinite(scores).all() or (scores < 0).any() or (scores > 1).any():
        raise ValueError("invalid research classifier scores")
    decisions = [
        SimpleNamespace(anomalous=bool(score >= FIXED_CUTOFF),
                        anomaly_score=float(score))
        for score in scores
    ]
    evaluation = metrics(dev, decisions)
    # Source-only development does not constitute the external acceptance gate.
    evaluation.pop("operational_gate", None)
    return {
        "status": "same_source_grouped_development_only_not_acceptance",
        "candidate": candidate,
        "feature_version_production_unchanged": FEATURE_VERSION,
        "research_feature_count": int(x_fit.shape[1]),
        "training_class_counts": {
            "benign": training["benign"], "anomaly": training["anomaly"]
        },
        "development_class_counts": {
            "benign": development["benign"], "anomaly": development["anomaly"]
        },
        "fixed_probability_cutoff": FIXED_CUTOFF,
        "dev_labels_used_for_fit_or_threshold": False,
        "group_disjoint": True,
        "evaluation": evaluation,
    }


def run(path: Path) -> dict:
    if path.stat().st_size != SOURCE_EXPECTED_BYTES or digest(path) != UNSW_SHA:
        raise ValueError("source archive size / sha256 not approved")
    with zipfile.ZipFile(path) as zf:
        events, scan = read_reservoir(zf, SOURCE_MEMBER, SAMPLE_CAP, SAMPLE_SEED)
    if digest(path) != UNSW_SHA:
        raise ValueError("source archive changed during scan")
    fit, dev, duplicate_count, groups = source_only_grouped_split(events)
    protocol = {
        "source_sha256": UNSW_SHA,
        "source_member": SOURCE_MEMBER,
        "sample_rows": SAMPLE_CAP,
        "sample_seed": SAMPLE_SEED,
        "split": "source_host_pair_proto_disjoint_75_25",
        "candidates": list(CANDIDATES),
        "estimator": dict(ESTIMATOR),
        "threshold": FIXED_CUTOFF,
        "minimum_per_class_in_each_partition": MIN_PER_CLASS,
        "production_feature_version": FEATURE_VERSION,
    }
    protocol_sha256 = hashlib.sha256(
        json.dumps(protocol, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    results = [fit_and_evaluate(fit, dev, candidate=key) for key in CANDIDATES]
    return {
        "schema_version": 1,
        "status": "source_only_supervised_candidates_research_completed",
        "research_only": True,
        "supervised_fit_labels": True,
        "operational_ml_acceptance_demonstrated": False,
        "production_model_changed": False,
        "auto_selected_winner": False,
        "ton_or_external_target_used": False,
        "protocol": protocol,
        "protocol_sha256": protocol_sha256,
        "source_scan": scan,
        "duplicate_records_excluded": duplicate_count,
        "source_host_pair_protocol_groups": groups,
        "source_fit_rows": len(fit),
        "source_dev_rows": len(dev),
        "dependency_versions": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "candidates": results,
        "limitations": [
            "One UNSW capture, with temporal overlap possible; NOT independent-site evidence.",
            "Real source attack labels are used for supervised fitting, not the shipped IF regime.",
            "No predeclared threshold optimization on development or external target labels.",
            "Source-only development has correlated traffic; Wilson intervals can be optimistic.",
            "Research candidates are not deployed Detector artifacts or signed production releases.",
            "No winner selected or model promoted; cannot claim operational acceptance.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unsw-zip", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refuse overwriting existing research evidence")
    report = run(args.unsw_zip)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as out:
        json.dump(report, out, indent=2, sort_keys=True, allow_nan=False)
        out.write("\n")
    print(json.dumps({
        "status": report["status"],
        "research_only": True,
        "candidate_metrics": [{
            "candidate": x["candidate"],
            "fpr": x["evaluation"]["fpr"],
            "recall": x["evaluation"]["recall"],
            "fpr_upper95": x["evaluation"]["fpr_wilson95"][1],
            "recall_lower95": x["evaluation"]["recall_wilson95"][0],
        } for x in report["candidates"]],
        "operational_ml_acceptance_demonstrated": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
