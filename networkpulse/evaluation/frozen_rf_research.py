"""Pinned, reproducible research RF freeze from exposed UNSW source captures.

FROZEN RESEARCH CANDIDATE ONLY. No production Detector substitution, signed
model claim, active registry release, or untouched holdout performance claim.
Never load joblib bytes from an untrusted source; check trusted expected SHA.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import zipfile
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer

from networkpulse.evaluation.live_unsw import read_reservoir
from networkpulse.evaluation.source_only_candidates import (
    CANDIDATES, ESTIMATOR, FIXED_CUTOFF, MIN_PER_CLASS, candidate_features,
)
from networkpulse.evaluation.source_only_feature_audit import SOURCE_EXPECTED_BYTES
from networkpulse.evaluation.source_only_loco import (
    MEMBERS, MEMBER_SEEDS, SAMPLE_PER_MEMBER,
)
from networkpulse.evaluation.unsw_to_toniot import UNSW_SHA, digest, unique
from networkpulse.features import FEATURE_VERSION

# Explicit researcher selection after *exposed* source-only development.
# The no-state/port-bucket representation avoids inventing a cross-sensor
# connection-state mapping and removes ordinal interpretation of port numbers.
# This rule is NOT validation on an untouched external target.
SELECTED = "rf_supervised_port_buckets_no_state"
RESEARCH_CONTRACT = "supervised_port_bucket_no_state_v1"
RESEARCH_BUNDLE_SCHEMA = 1


def fixed_protocol() -> dict:
    return {
        "raw_source_sha256": UNSW_SHA,
        "sample_members": list(MEMBERS),
        "source_sample_caps": SAMPLE_PER_MEMBER,
        "source_sample_seeds": list(MEMBER_SEEDS),
        "dedup": "canonical_key_and_normalized_flow_fingerprint",
        "research_selected_candidate": SELECTED,
        "selection_basis": "source_only_exposed_loco_plus_sensor_semantics_manual",
        "source_only_loco_folds": 4,
        "training_scope": "all_four_exposed_UNSW_capture_samples",
        "feature_contract": RESEARCH_CONTRACT,
        "production_feature_version_unchanged": FEATURE_VERSION,
        "estimator": dict(ESTIMATOR),
        "fixed_cutoff": FIXED_CUTOFF,
        "minimum_per_class": MIN_PER_CLASS,
    }


def protocol_sha256() -> str:
    return hashlib.sha256(
        json.dumps(fixed_protocol(), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def validate_loco_result(loco: dict) -> None:
    """No research candidate freeze if all 4 preregistered source folds unproven."""
    if loco.get("status") != "exposed_source_loco_research_completed":
        raise ValueError("authentic exposed-source LOCO report required")
    if (loco.get("operational_acceptance_demonstrated") is not False
            or loco.get("independent_site_verified") is not False
            or loco.get("automatic_winner_selected") is not False):
        raise ValueError("source report misrepresents independent acceptance")
    if loco.get("protocol", {}).get("source_sha256") != UNSW_SHA:
        raise ValueError("LOCO source checksum mismatch")
    folds = loco.get("folds", [])
    if [f.get("excluded_capture") for f in folds] != list(MEMBERS):
        raise ValueError("required source LOCO folds are missing")
    for fold in folds:
        if fold.get("status") != "measured_exposed_source_capture_development_only":
            raise ValueError("insufficient labeled source fold: freeze blocked")
        result = fold.get("models", {}).get(SELECTED, {})
        if (result.get("status") != "measured_same_source_cross_capture_not_acceptance"
                or result.get("research_numeric_thresholds_met") is not True):
            raise ValueError("predeclared source-fold research gates not demonstrated")
        counts = result.get("class_counts", {})
        if any(counts.get(label, 0) < MIN_PER_CLASS
               for label in ("benign", "anomaly")):
            raise ValueError("insufficient source-only fold class support")


def fit_from_approved_source(path: Path):
    if path.stat().st_size != SOURCE_EXPECTED_BYTES or digest(path) != UNSW_SHA:
        raise ValueError("UNSW source length or SHA256 failed")
    records = []
    capture_scans = {}
    with zipfile.ZipFile(path) as archive:
        for member, seed in zip(MEMBERS, MEMBER_SEEDS):
            sample, scan = read_reservoir(
                archive, member, SAMPLE_PER_MEMBER, seed
            )
            if len(sample) != SAMPLE_PER_MEMBER:
                raise ValueError("source member lacks enough authentic rows")
            records.extend(sample)
            capture_scans[member] = scan
    if digest(path) != UNSW_SHA:
        raise ValueError("raw UNSW archive modified during training")
    selected, dropped = unique(records)
    counts = Counter(e.label for e in selected)
    if any(counts[label] < MIN_PER_CLASS for label in ("benign", "anomaly")):
        raise ValueError("source training lacks genuine class support")
    if SELECTED not in CANDIDATES:
        raise ValueError("unregistered source-side research representation")
    vectorizer = DictVectorizer(sparse=False)
    features = vectorizer.fit_transform([candidate_features(e, SELECTED) for e in selected])
    labels = np.asarray([int(e.label == "anomaly") for e in selected], dtype=int)
    model = RandomForestClassifier(**ESTIMATOR)
    model.fit(features, labels)
    if tuple(model.classes_) != (0, 1):
        raise ValueError("research supervised classes incomplete")
    # This bundle is trusted *only if* the caller pins its SHA-256 out of band.
    bundle = {
        "schema_version": RESEARCH_BUNDLE_SCHEMA,
        "research_only": True,
        "production_approved": False,
        "feature_contract": RESEARCH_CONTRACT,
        "research_candidate": SELECTED,
        "feature_count": int(features.shape[1]),
        "source_sha256": UNSW_SHA,
        "protocol_sha256": protocol_sha256(),
        "fixed_cutoff": FIXED_CUTOFF,
        "python_version": platform.python_version(),
        "numpy_version": np.__version__,
        "sklearn_version": sklearn.__version__,
        "vectorizer": vectorizer,
        "estimator": model,
    }
    # No flow-level IP/UID/row data are serialized to the bundle.
    manifest = {
        "schema_version": 1,
        "status": "source_only_supervised_research_bundle_frozen",
        "research_only": True,
        "production_model_changed": False,
        "production_approved": False,
        "operator_signed": False,
        "independent_site_evaluated": False,
        "selected_candidate": SELECTED,
        "selection_method": "posthoc_exposed_source_only_human_research_choice",
        "source_zip_sha256": UNSW_SHA,
        "protocol": fixed_protocol(),
        "protocol_sha256": protocol_sha256(),
        "source_scans": capture_scans,
        "training_sample_before_dedup": len(records),
        "training_unique": len(selected),
        "duplicates_excluded": dropped,
        "training_class_counts": {
            "benign": counts["benign"], "anomaly": counts["anomaly"]
        },
        "feature_count": int(features.shape[1]),
        "dependency_versions": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
            "joblib": joblib.__version__,
        },
        "training_dataset_row_ledger": (
            "not_exported: raw network identifiers and normalized fingerprints "
            "must be stored in a separately access-controlled source ledger"
        ),
        "limitations": [
            "All four previously exposed controlled UNSW captures used for training.",
            "Research RF is not a compatible production Detector object.",
            "The model bundle has a SHA-256 integrity pin but NO trusted release signature.",
            "No source per-flow ID ledger exported into the artifact.",
            "Requires independent unchanged-model prospective site evaluation.",
            "No deployment, production false-positive or operator review evidence.",
        ],
    }
    return bundle, manifest, selected[:32]


def score_verified_bundle(bundle: dict, events) -> np.ndarray:
    """Only use with in-process trusted or SHA-pinned locally loaded bundles."""
    if (bundle.get("schema_version") != 1
            or bundle.get("research_only") is not True
            or bundle.get("production_approved") is not False
            or bundle.get("research_candidate") != SELECTED
            or bundle.get("feature_contract") != RESEARCH_CONTRACT
            or bundle.get("protocol_sha256") != protocol_sha256()
            or bundle.get("source_sha256") != UNSW_SHA
            or bundle.get("fixed_cutoff") != FIXED_CUTOFF
            or bundle.get("sklearn_version") != sklearn.__version__):
        raise ValueError("research model bundle version/source/contract mismatch")
    x = bundle["vectorizer"].transform([
        candidate_features(e, SELECTED) for e in events
    ])
    if x.shape[1] != bundle["feature_count"]:
        raise ValueError("wrong research feature dimension")
    scores = bundle["estimator"].predict_proba(x)[:, 1]
    if not np.isfinite(scores).all() or (scores < 0).any() or (scores > 1).any():
        raise ValueError("invalid finite research probability scores")
    return scores


def verify_bundle_checksum(path: Path, expected_sha256: str) -> str:
    if (not isinstance(expected_sha256, str) or len(expected_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_sha256)):
        raise ValueError("expected bundle SHA256 must be out-of-band lowercase hex")
    actual = digest(path)
    if actual != expected_sha256:
        raise ValueError("research model bundle SHA256 mismatch; refuse deserialization")
    return actual


def run(unsw_zip: Path, loco_report: Path, destination: Path, report_path: Path) -> dict:
    if destination.exists() or report_path.exists():
        raise ValueError("refuse to replace existing research bundle or manifest")
    loco = json.loads(loco_report.read_text(encoding="utf-8"))
    validate_loco_result(loco)
    bundle, manifest, selftest = fit_from_approved_source(unsw_zip)
    destination.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, destination, compress=3)
    file_sha = digest(destination)
    try:
        verify_bundle_checksum(destination, file_sha)
        # Only our *locally created* bytes are reloaded; no external untrusted pickle.
        reloaded = joblib.load(destination)
        a = score_verified_bundle(bundle, selftest)
        b = score_verified_bundle(reloaded, selftest)
        if not np.array_equal(a, b):
            raise ValueError("candidate model serialization changed predictions")
        manifest["bundle_sha256"] = file_sha
        manifest["bundle_bytes"] = destination.stat().st_size
        manifest["selftest_rows"] = len(selftest)
        manifest["selftest_probability_sha256"] = hashlib.sha256(
            a.astype("<f8").tobytes()
        ).hexdigest()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with report_path.open("x", encoding="utf-8") as out:
            json.dump(manifest, out, indent=2, sort_keys=True, allow_nan=False)
            out.write("\n")
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unsw-zip", type=Path, required=True)
    parser.add_argument("--loco-report", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    manifest = run(args.unsw_zip, args.loco_report, args.bundle, args.manifest)
    print(json.dumps({
        "status": manifest["status"],
        "bundle_sha256": manifest["bundle_sha256"],
        "trained_flows": manifest["training_unique"],
        "production_approved": False,
        "independent_site_evaluated": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
