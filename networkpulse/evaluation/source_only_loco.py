"""Pre-registered four-fold within-UNSW leave-one-capture-out experiment.

All four captures are *exposed source development* after earlier analysis.
Never call them virgin external holdouts, independent physical sites, or
production acceptance. No TON/CIC data, target threshold search or promotion.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import zipfile
from collections import Counter
from pathlib import Path

import numpy as np
import sklearn

from networkpulse.evaluation.live_unsw import read_reservoir
from networkpulse.evaluation.source_only_capture_stress import (
    fit_source_model, score_capture,
)
from networkpulse.evaluation.source_only_candidates import (
    CANDIDATES, ESTIMATOR, FIXED_CUTOFF, MIN_PER_CLASS,
)
from networkpulse.evaluation.source_only_feature_audit import SOURCE_EXPECTED_BYTES
from networkpulse.evaluation.unsw_to_toniot import UNSW_SHA, digest, unique
from networkpulse.generalization_evidence import normalized_flow_fingerprint

MEMBERS = (
    "UNSW-NB15_1.csv", "UNSW-NB15_2.csv",
    "UNSW-NB15_3.csv", "UNSW-NB15_4.csv",
)
SAMPLE_PER_MEMBER = 6000
MEMBER_SEEDS = (60, 61, 62, 63)


def host_pair_group(event):
    return (str(event.src_ip), str(event.dst_ip), event.proto)


def evaluate_fold(samples, excluded_member: str):
    """Leave exactly one source capture unused at fitting time."""
    if tuple(samples) != MEMBERS or excluded_member not in MEMBERS:
        raise ValueError("fold capture registry must be complete and predeclared")
    fit_candidates = []
    for member in MEMBERS:
        if member != excluded_member:
            fit_candidates.extend(samples[member])
    source_fit, removed_fit = unique(fit_candidates)
    target, removed_target = unique(
        samples[excluded_member],
        {e.key() for e in source_fit},
        {normalized_flow_fingerprint(e) for e in source_fit},
    )
    fit_counts = Counter(e.label for e in source_fit)
    dev_counts = Counter(e.label for e in target)
    common_groups = len(
        {host_pair_group(e) for e in source_fit} &
        {host_pair_group(e) for e in target}
    )
    base = {
        "excluded_capture": excluded_member,
        "fit_members": [m for m in MEMBERS if m != excluded_member],
        "fit_rows": len(source_fit),
        "dev_rows": len(target),
        "fit_class_counts": {
            "benign": fit_counts["benign"], "anomaly": fit_counts["anomaly"],
        },
        "dev_class_counts": {
            "benign": dev_counts["benign"], "anomaly": dev_counts["anomaly"],
        },
        "duplicates_excluded_from_fit": removed_fit,
        "exact_flow_overlaps_or_duplicates_excluded_from_dev": removed_target,
        "shared_host_pair_protocol_groups": common_groups,
        "physically_independent_site": False,
        "time_independence_not_proven": True,
    }
    if any(
        counts[label] < MIN_PER_CLASS
        for counts in (fit_counts, dev_counts)
        for label in ("benign", "anomaly")
    ):
        base["status"] = "blocked_insufficient_natural_class_support"
        base["models"] = {}
        return base
    models = {}
    fit_keys = frozenset(e.key() for e in source_fit)
    fit_fps = frozenset(normalized_flow_fingerprint(e) for e in source_fit)
    for candidate in CANDIDATES:
        frozen_at_fit = fit_source_model(source_fit, candidate)
        # Caller removed overlaps already; this second check fails closed if
        # a regression attempts to contaminate development with FIT flows.
        result = score_capture(
            frozen_at_fit, candidate, target,
            fit_fingerprints=fit_fps, fit_ids=fit_keys,
        )
        if result["overlapping_or_duplicate_events_excluded"] != 0:
            raise ValueError("unexpected FIT/DEV source overlap after de-dup")
        models[candidate] = result
    base["status"] = "measured_exposed_source_capture_development_only"
    base["models"] = models
    return base


def run(path: Path) -> dict:
    if path.stat().st_size != SOURCE_EXPECTED_BYTES or digest(path) != UNSW_SHA:
        raise ValueError("unapproved source archive bytes or SHA256")
    with zipfile.ZipFile(path) as zf:
        samples = {}
        scan = {}
        for member, seed in zip(MEMBERS, MEMBER_SEEDS):
            sample, info = read_reservoir(
                zf, member, SAMPLE_PER_MEMBER, seed
            )
            if len(sample) != SAMPLE_PER_MEMBER:
                raise ValueError("insufficient original capture rows")
            samples[member] = sample
            scan[member] = info
    if digest(path) != UNSW_SHA:
        raise ValueError("approved UNSW source ZIP changed during scan")
    folds = [evaluate_fold(samples, member) for member in MEMBERS]
    protocol = {
        "source_sha256": UNSW_SHA,
        "members": list(MEMBERS),
        "sample_per_member": SAMPLE_PER_MEMBER,
        "seeds": list(MEMBER_SEEDS),
        "fit": "all other three UNSW source captures",
        "evaluation": "one excluded previously inspected UNSW source capture",
        "fit_labels": "supervised source fit only",
        "fixed_cutoff": FIXED_CUTOFF,
        "predeclared_models": list(CANDIDATES),
        "estimator": dict(ESTIMATOR),
        "min_class_per_partition": MIN_PER_CLASS,
    }
    signature = hashlib.sha256(
        json.dumps(protocol, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "schema_version": 1,
        "status": "exposed_source_loco_research_completed",
        "research_only": True,
        "production_model_changed": False,
        "independent_site_verified": False,
        "operational_acceptance_demonstrated": False,
        "automatic_winner_selected": False,
        "no_ton_or_external_target_used": True,
        "source": "UNSW-NB15 controlled cyber range all 4 raw capture members",
        "protocol": protocol,
        "protocol_sha256": signature,
        "dependency_versions": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "source_scans": scan,
        "folds": folds,
        "limitations": [
            "The four captures have already been exposed in prior research.",
            "Same controlled UNSW cyber range, not independently operated field sites.",
            "Pooled training shares lab protocol/state conventions and some host pairs.",
            "Training uses only source-fit labels; held-out capture labels are metrics only.",
            "LOCO metrics are development and cannot validate an untouched real site.",
            "Wilson intervals ignore correlated sessions and can understate uncertainty.",
            "No frozen signed/active native Detector, automatic selection or deployment.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unsw-zip", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to replace immutable research output")
    report = run(args.unsw_zip)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True, allow_nan=False)
        output.write("\n")
    print(json.dumps({
        "status": report["status"],
        "folds": [
            {"capture": fold["excluded_capture"], "status": fold["status"],
             "class_counts": fold["dev_class_counts"],
             "models": {
                 name: {
                     "fpr": record["metrics"]["fpr"] if record["metrics"] else None,
                     "recall": record["metrics"]["recall"] if record["metrics"] else None,
                     "numeric_gate": record.get("research_numeric_thresholds_met"),
                 } for name, record in fold["models"].items()
             }}
            for fold in report["folds"]
        ],
        "operational_acceptance_demonstrated": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
