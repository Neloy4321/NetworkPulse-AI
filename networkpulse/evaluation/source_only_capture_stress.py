"""Same-source cross-capture *stress diagnostics*; never independent ML acceptance.

Predeclared UNSW captures 2/3/4, only one SHA-pinned ZIP. Source FIT is taken
from capture 1 with fixed seed/group split. Scores on captures 2/3/4 do not
influence training, threshold, features, hyperparameters or candidate choice.
Capture 4 was already inspected in previous research: no untouched claims.
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
from networkpulse.evaluation.source_only_candidates import (
    CANDIDATES, ESTIMATOR, FIXED_CUTOFF, MIN_PER_CLASS, candidate_features,
)
from networkpulse.evaluation.source_only_feature_audit import (
    SAMPLE_CAP, SAMPLE_SEED, SOURCE_EXPECTED_BYTES, SOURCE_MEMBER,
    source_only_grouped_split,
)
from networkpulse.evaluation.unsw_to_toniot import UNSW_SHA, digest, metrics, unique
from networkpulse.generalization_evidence import normalized_flow_fingerprint

CAPTURE_MEMBERS = ("UNSW-NB15_2.csv", "UNSW-NB15_3.csv", "UNSW-NB15_4.csv")
CAPTURE_CAP = 8000
_MAX_FPR_UPPER = 0.05
_MIN_RECALL_LOWER = 0.8


def fit_source_model(fit, candidate):
    """Only FIT labels are inspected. Neither dev nor capture labels tune model."""
    if candidate not in CANDIDATES:
        raise ValueError("candidate not pre-registered")
    counts = Counter(e.label for e in fit)
    if any(counts[label] < MIN_PER_CLASS for label in ("benign", "anomaly")):
        raise ValueError("source FIT requires genuine two-class label support")
    vectorizer = DictVectorizer(sparse=False)
    x = vectorizer.fit_transform([candidate_features(e, candidate) for e in fit])
    y = np.fromiter((int(e.label == "anomaly") for e in fit), dtype=int)
    model = RandomForestClassifier(**ESTIMATOR)
    model.fit(x, y)
    if tuple(model.classes_) != (0, 1):
        raise ValueError("incomplete genuine FIT labels")
    return vectorizer, model


def score_capture(model_bundle, candidate, capture_events, *, fit_fingerprints, fit_ids):
    vectorizer, model = model_bundle
    events, excluded = unique(capture_events, fit_ids, fit_fingerprints)
    counts = Counter(e.label for e in events)
    result = {
        "status": "blocked_insufficient_capture_class_support",
        "scope": "same_UNSW_family_prior_inspected_captures_not_independent",
        "candidate": candidate,
        "rows_after_exact_overlap_exclusion": len(events),
        "overlapping_or_duplicate_events_excluded": excluded,
        "class_counts": {
            "benign": counts["benign"], "anomaly": counts["anomaly"]
        },
        "metrics": None,
    }
    if counts["benign"] < MIN_PER_CLASS or counts["anomaly"] < MIN_PER_CLASS:
        return result
    x = vectorizer.transform([candidate_features(e, candidate) for e in events])
    scores = model.predict_proba(x)[:, 1]
    if not np.isfinite(scores).all() or (scores < 0).any() or (scores > 1).any():
        raise ValueError("non-finite or invalid model output")
    predictions = [
        SimpleNamespace(anomalous=bool(s >= FIXED_CUTOFF), anomaly_score=float(s))
        for s in scores
    ]
    report = metrics(events, predictions)
    report.pop("operational_gate", None)  # Avoid external-site acceptance conflation.
    bounds = report["fpr_wilson95"], report["recall_wilson95"]
    result.update({
        "status": "measured_same_source_cross_capture_not_acceptance",
        "metrics": report,
        "research_numeric_thresholds_met": (
            bounds[0][1] <= _MAX_FPR_UPPER and bounds[1][0] >= _MIN_RECALL_LOWER
        ),
        "training_or_threshold_changed_after_capture_labels": False,
    })
    return result


def run(path: Path) -> dict:
    if path.stat().st_size != SOURCE_EXPECTED_BYTES or digest(path) != UNSW_SHA:
        raise ValueError("refusing archive with unexpected bytes or SHA256")
    with zipfile.ZipFile(path) as zf:
        source, source_info = read_reservoir(zf, SOURCE_MEMBER, SAMPLE_CAP, SAMPLE_SEED)
        fit, dev, _, group_count = source_only_grouped_split(source)
        # Fingerprints are computed only for de-duplication, never used as model features.
        fit_ids = frozenset(e.key() for e in fit)
        fit_fingerprints = frozenset(normalized_flow_fingerprint(e) for e in fit)
        models = {name: fit_source_model(fit, name) for name in CANDIDATES}
        captures = []
        for i, member in enumerate(CAPTURE_MEMBERS, 1):
            events, scanned = read_reservoir(
                zf, member, CAPTURE_CAP, SAMPLE_SEED + i
            )
            compared = {
                candidate: score_capture(
                    models[candidate], candidate, events,
                    fit_fingerprints=fit_fingerprints, fit_ids=fit_ids,
                )
                for candidate in CANDIDATES
            }
            captures.append({
                "member": member,
                "full_source_scan": scanned,
                "measured_from_source_capture_1_fit": compared,
            })
    if digest(path) != UNSW_SHA:
        raise ValueError("source archive mutated during stress assessment")
    protocol = {
        "source_sha256": UNSW_SHA,
        "source_fit_member": SOURCE_MEMBER,
        "sample_cap_fit_source": SAMPLE_CAP,
        "fixed_source_seed": SAMPLE_SEED,
        "source_split": "host_pair_protocol_group_75_25",
        "source_group_count": group_count,
        "source_dev_labels_never_fit": True,
        "capture_members": list(CAPTURE_MEMBERS),
        "capture_sample_cap": CAPTURE_CAP,
        "capture_sample_seeds": [SAMPLE_SEED + i for i in range(1, 4)],
        "min_class_count": MIN_PER_CLASS,
        "candidates": list(CANDIDATES),
        "estimator": dict(ESTIMATOR),
        "cutoff": FIXED_CUTOFF,
        "research_upper_fpr_bound": _MAX_FPR_UPPER,
        "research_lower_recall_bound": _MIN_RECALL_LOWER,
    }
    protocol_sha = hashlib.sha256(
        json.dumps(protocol, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "schema_version": 1,
        "status": "same_source_cross_capture_stress_completed",
        "research_only": True,
        "operational_acceptance_demonstrated": False,
        "production_model_changed": False,
        "independent_site_verified": False,
        "source_fit_count": len(fit),
        "source_dev_count_not_used_for_fit": len(dev),
        "source_scan": source_info,
        "protocol": protocol,
        "protocol_sha256": protocol_sha,
        "dependencies": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "captures": captures,
        "limitations": [
            "Within the same UNSW lab and sensor family; NOT independent site acceptance.",
            "Capture 4 and archive semantics were previously inspected; no untouched claim.",
            "Capture labels are only read for post-score metrics; no model tuning or winner selection.",
            "Source-fit and capture de-dup only detects exact normalized overlaps among sampled rows.",
            "Source-group-disjoint training/dev split is not chronologically disjoint.",
            "Fixed 8000-row reservoirs alter prevalence; Wilson CIs ignore correlated flows.",
            "Signed deployed native Detector is unchanged; research RandomForests are not shipped.",
            "Research numerical thresholds are descriptive, not production acceptance.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unsw-zip", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite stress evidence")
    result = run(args.unsw_zip)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as out:
        json.dump(result, out, indent=2, sort_keys=True, allow_nan=False)
        out.write("\n")
    print(json.dumps({
        "status": result["status"],
        "capture_results": [{
            "member": c["member"],
            "models": {
                name: {
                    "status": report["status"],
                    "class_counts": report["class_counts"],
                    "fpr": report["metrics"]["fpr"] if report["metrics"] else None,
                    "recall": report["metrics"]["recall"] if report["metrics"] else None,
                    "research_numeric_thresholds_met": report.get(
                        "research_numeric_thresholds_met"
                    ),
                } for name, report in c["measured_from_source_capture_1_fit"].items()
            },
        } for c in result["captures"]],
        "operational_acceptance_demonstrated": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
