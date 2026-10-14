"""Validated, immutable, reproducible native Detector candidate preparation.

Real, user-authorized metadata stays private. Manifests contain only checksums,
counts, bounded metrics and provenance *declarations*, not raw flow IPs/rows.
No automatic production promotion; operator + independent-site gates remain.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
from datetime import timezone
from pathlib import Path

from networkpulse.data_quality import quality_report
from networkpulse.detector import train
from networkpulse.features import FEATURE_VERSION
from networkpulse.model_registry import sha256
from networkpulse.schemas import FlowEvent

_RELEASE_SCHEMA = 1
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_SOURCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _digest_keys(events: list[FlowEvent]) -> str:
    digest = hashlib.sha256()
    for event in events:
        digest.update(event.key().encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def validate_training_input(
    events: list[FlowEvent], *, max_events: int = 20000,
    min_boundary_gap_seconds: float = 0.0,
) -> dict:
    """Enforce exactly the 60/15/25 split used by Detector.train.

    Future feature/temporal split changes must update this checker and tests.
    """
    if not 100 <= max_events <= 100000 or len(events) < 100:
        raise ValueError("training requires >=100 rows and a valid row cap")
    if len(events) > max_events:
        raise ValueError("dataset exceeds training row cap: refuse truncation/sampling")
    if not 0 <= min_boundary_gap_seconds <= 86400:
        raise ValueError("invalid split boundary gap")
    quality = quality_report(events)
    if quality["duplicate_count"]:
        raise ValueError("duplicate event identity detected: deduplicate before training")
    if not quality["chronological_order"]:
        raise ValueError("dataset must be sorted by UTC event time before training")
    if any(e.label not in ("benign", "anomaly") for e in events):
        raise ValueError("candidate release requires independently reviewed complete labels")
    if len({e.source for e in events}) != 1:
        raise ValueError("mixed source contracts require a separately audited mapping")
    count = len(events)
    a, b = int(count * .60), int(count * .75)
    spans = [(0, a), (a, b), (b, count)]
    boundaries = (
        (events[a].timestamp - events[a - 1].timestamp).total_seconds(),
        (events[b].timestamp - events[b - 1].timestamp).total_seconds(),
    )
    if min(boundaries) <= min_boundary_gap_seconds:
        raise ValueError("train/calibration/holdout time boundaries overlap or violate embargo")
    fit = [e for e in events[:a] if e.label == "benign"]
    calibration = [e for e in events[a:b] if e.label == "benign"]
    holdout = events[b:]
    benign_holdout = sum(e.label == "benign" for e in holdout)
    attack_holdout = sum(e.label == "anomaly" for e in holdout)
    if len(fit) < 50 or len(calibration) < 20:
        raise ValueError("not enough benign fitting/calibration examples")
    if benign_holdout < 20 or attack_holdout < 5:
        raise ValueError("insufficient labeled holdout classes to certify candidate gates")
    return {
        "feature_contract": FEATURE_VERSION,
        "record_count": count,
        "chronological": True,
        "exact_duplicates": 0,
        "source_counts": quality["sources"],
        "label_counts": quality["labels"],
        "sampled_or_truncated_by_pipeline": False,
        "split_method": "strict_input_chronological_60_15_25",
        "split_counts": {"train_total": a, "calibration_total": b - a,
                         "holdout_total": count - b,
                         "fit_benign": len(fit), "calibration_benign": len(calibration),
                         "holdout_benign": benign_holdout, "holdout_anomaly": attack_holdout},
        "split_time_gaps_seconds": [round(x, 6) for x in boundaries],
        "embargo_requirement_seconds": min_boundary_gap_seconds,
        "split_windows_utc": [
            {"role": role,
             "start": events[i].timestamp.astimezone(timezone.utc).isoformat(),
             "end": events[j-1].timestamp.astimezone(timezone.utc).isoformat()}
            for (role, (i, j)) in zip(("fit", "calibration", "holdout"), spans)
        ],
        "event_identity_sha256": _digest_keys(events),
    }


def build_candidate(
    events: list[FlowEvent], *, name: str, root: Path,
    dataset_sha256: str, source_id: str,
    seed: int = 42, quantile: float = .97,
    max_events: int = 20000, min_boundary_gap_seconds: float = 0.0,
    min_f1: float = 0.0, max_alert_fraction: float = 1.0,
    max_fpr_upper_95: float | None = None,
    dataset_selection: str = "operator_supplied_not_independently_audited",
) -> dict:
    """Train + stage never-overwritten artifact/manifest under root/name.

    Caller MUST verify the raw dataset SHA (if a local file exists) before
    passing it; a declared checksum is lineage only, not provenance authority.
    The source identity is deliberately not a URL or on-disk path.
    """
    if not _NAME.fullmatch(name) or not _SOURCE.fullmatch(source_id):
        raise ValueError("invalid candidate/source identifier")
    if not _DIGEST.fullmatch(dataset_sha256):
        raise ValueError("64-digit lowercase dataset SHA-256 required")
    if not isinstance(seed, int) or not 0 <= seed <= 2**32 - 1:
        raise ValueError("invalid training seed")
    if not 0 <= min_f1 <= 1 or not 0 < max_alert_fraction <= 1:
        raise ValueError("invalid candidate release gates")
    if max_fpr_upper_95 is not None and not 0 < max_fpr_upper_95 <= 1:
        raise ValueError("invalid FPR upper bound gate")
    if dataset_selection not in (
        "complete_canonical_file",
        "reservoir_sample_of_verified_raw_capture",
        "operator_supplied_not_independently_audited",
    ):
        raise ValueError("unsupported dataset selection provenance")

    audited = validate_training_input(
        events, max_events=max_events,
        min_boundary_gap_seconds=min_boundary_gap_seconds,
    )
    if "simulator" in audited["source_counts"] or "synthetic" in source_id.lower():
        # The model may still be useful in isolated development, but may not
        # masquerade as a field-validated candidate.
        source = "synthetic_demo_training_release"
        synthetic = True
    else:
        source = source_id
        synthetic = False

    trained = train(events, seed=seed, quantile=quantile, source=source)
    metrics = trained.metadata.get("metrics")
    if not isinstance(metrics, dict):
        raise ValueError("no held-out labeled metrics: refuse candidate")
    f1 = float(metrics.get("f1", -1))
    alert_fraction = metrics["alerts"] / audited["split_counts"]["holdout_total"]
    if not math.isfinite(f1) or f1 < min_f1 or alert_fraction > max_alert_fraction:
        raise ValueError("candidate failed held-out F1 or alert-budget release gate")
    if max_fpr_upper_95 is not None:
        upper = metrics.get("fpr_wilson_upper_95_one_sided")
        benign = int(metrics.get("benign_count", 0))
        if upper is None or benign < 100 or not math.isfinite(float(upper)) or float(upper) > max_fpr_upper_95:
            raise ValueError("candidate failed held-out benign FPR uncertainty release gate")

    # Functional fingerprint is reproducible for the same data/seed/code even
    # though byte-identical joblib is not promised (trained_at differs).
    holdout = events[int(len(events)*.75):]
    predictions = trained.score(holdout)
    functional = hashlib.sha256(json.dumps({
        "threshold": round(trained.threshold, 8),
        "scores": [x.anomaly_score for x in predictions],
        "flags": [x.anomalous for x in predictions],
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    root = Path(root)
    destination = root / name
    root.mkdir(parents=True, exist_ok=True)
    destination.mkdir(mode=0o700)  # fails if already exists: immutable names
    artifact = destination / "model.joblib"
    manifest_file = destination / "manifest.json"
    try:
        trained.save(artifact)
        digest = sha256(artifact)
        manifest = {
            "schema_version": _RELEASE_SCHEMA,
            "candidate": name,
            "model": {
                "sha256": digest, "filename": "model.joblib",
                "feature_version": FEATURE_VERSION,
                "source": source,
                "synthetic_only": synthetic,
                "trained_at": trained.metadata["trained_at"],
                "seed": seed, "quantile": quantile,
                "functional_holdout_sha256": functional,
            },
            "dataset": {
                "source_id": source_id,
                "raw_source_sha256": dataset_sha256,
                "selection": dataset_selection,
                "source_authenticity_independently_verified": False,
                "ground_truth_labels_independently_verified": False,
                **audited,
            },
            "validation": {
                "heldout_metrics": metrics,
                "gate": {"min_f1": min_f1,
                         "max_alert_fraction": max_alert_fraction,
                         "max_fpr_upper_95": max_fpr_upper_95},
                "observed_holdout_alert_fraction": round(alert_fraction, 6),
            },
            "release": {
                "state": "candidate_not_deployed",
                "independent_site_validation": False,
                "human_production_approval": False,
                "production_promotion": "forbidden_without_separate_registry_policy",
            },
            "warning": "Source/label assertions and SHA checks do not authenticate "
                       "site independence or prove real-world intrusion performance.",
        }
        with manifest_file.open("x", encoding="utf-8") as stream:
            json.dump(manifest, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        return {"candidate": name, "directory": str(destination),
                "model_path": str(artifact), "manifest_path": str(manifest_file),
                "model_sha256": digest, "dataset_sha256": dataset_sha256,
                "functional_holdout_sha256": functional, "metrics": metrics,
                "state": "candidate_not_deployed"}
    except BaseException:
        shutil.rmtree(destination)
        raise


def verify_candidate(directory: Path) -> dict:
    """Verify staged manifest and artifact bytes without unpickling anything."""
    directory = Path(directory)
    with (directory / "manifest.json").open(encoding="utf-8") as file:
        manifest = json.load(file)
    if not isinstance(manifest, dict) or manifest.get("schema_version") != _RELEASE_SCHEMA:
        raise ValueError("unsupported candidate manifest")
    if not isinstance(manifest.get("model"), dict):
        raise ValueError("missing model release metadata")
    expected = manifest["model"].get("sha256")
    if not isinstance(expected, str) or not _DIGEST.fullmatch(expected):
        raise ValueError("invalid manifest model checksum")
    if manifest["model"].get("filename") != "model.joblib":
        raise ValueError("unapproved candidate filename")
    if not _NAME.fullmatch(str(manifest.get("candidate", ""))) or directory.name != manifest["candidate"]:
        raise ValueError("candidate name/path mismatch")
    actual = sha256(directory / "model.joblib")
    if actual != expected:
        raise ValueError("candidate model artifact integrity failed")
    return {"candidate": manifest["candidate"], "sha256": actual,
            "state": manifest.get("release", {}).get("state"),
            "synthetic_only": manifest["model"].get("synthetic_only"),
            "integrity": "verified_without_unpickling",
            "warning": "Integrity is not provenance, signature or site validation."}
