"""IoT-SFC preregistration and frozen V2 identity verification without reading target CSV.

Strictly research-only. This module never unpickles models, parses target
CSV headers/labels, trains, scores, or uploads raw records.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path

PROTOCOL = Path(__file__).resolve().parents[2] / (
    "docs/P0_IOT_SFC_V2_FROZEN_PREREGISTRATION.json"
)
MODEL_SHA = "cd239783fd4318c0c4e897f1d451c2d5af4b42132979c79a4e489df626f538a5"
MODEL_PROTOCOL_SHA = "3810aeb3f9510e2b6e736923ec7a44798fad9d37a56e3d27140c15a0f37fcfde"
TARGET_SHA = "070b1356e5bd296e584109fae79139cfe0f20ff4790f69e42994d67362cb9f62"
TARGET_MD5 = "6b858e337a8241b89f4d76f9a1454a60"
TARGET_SIZE = 776500807
CSV_SIZE = 13561863941
FEATURE_CONTRACT = "missingness_aware_flow_v2"


def _json_object(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 250_000:
        raise ValueError("Missing, oversized, or symlinked metadata JSON")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Metadata must be a JSON object")
    return data


def _regular_file(path: Path) -> None:
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("Model must be a regular file, not a symlink")


def _sha256(path: Path) -> str:
    _regular_file(path)
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _require_fields(actual: dict, pinned: dict) -> None:
    for key, value in pinned.items():
        observed = actual.get(key)
        if type(observed) is not type(value) or observed != value:
            raise ValueError("Immutable preregistration field differs: " + key)


def validate_preregistration(spec: dict) -> None:
    _require_fields(spec, {
        "schema_version": 1,
        "protocol_id": "networkpulse-iot-sfc-v2-2026-10-23-research-holdout-v1",
        "status": "PREREGISTERED_NOT_SCORED",
        "scope": "public_laboratory_transfer_research_only",
        "operational_ml_acceptance": "NO_GO",
    })
    model, target, gates, analysis = (
        spec["model"], spec["target"], spec["numeric_gates"],
        spec["frozen_analysis_plan"],
    )
    _require_fields(model, {
        "kind": "V2_source_calibrated_unsigned_RandomForest",
        "artifact_sha256": MODEL_SHA,
        "source_manifest_protocol_sha256": MODEL_PROTOCOL_SHA,
        "threshold": 0.2,
        "feature_contract": FEATURE_CONTRACT,
        "production_signed": False,
        "source_model_github_run": 38909855312,
        "source_model_artifact_id": 12050072139,
        "source_manifest_artifact_id": 12049488464,
        "original_calibration_outcomes_already_exposed": True,
    })
    _require_fields(target, {
        "name": "IoT-SFC v2",
        "zenodo_record": "https://zenodo.org/records/23371775",
        "archive_basename": "iot_dataset_v7.zip",
        "archive_size_bytes": TARGET_SIZE,
        "archive_md5": TARGET_MD5,
        "archive_sha256": TARGET_SHA,
        "single_csv_member": "iot_dataset_v7.csv",
        "declared_csv_size_bytes": CSV_SIZE,
        "label_or_header_cells_inspected": False,
        "archive_member_crc_verified": False,
        "archive_sha256_origin": (
            "user_executed_local_preflight_report_not_independently_downloaded"
        ),
        "independently_operated_field_site": False,
        "license_and_permitted_use_verified": False,
        "ground_truth_per_flow_adjudicated": False,
    })
    _require_fields(gates, {
        "fpr_wilson_95_upper_max": 0.05,
        "recall_wilson_95_lower_min": 0.8,
        "min_natural_benign": 200,
        "min_natural_attack": 100,
        "min_distinct_capture_days": 3,
        "require_per_day_metrics": True,
        "require_cluster_aware_uncertainty_review": True,
        "require_zero_training_target_overlap": True,
    })
    _require_fields(analysis, {
        "training_on_iot_sfc_labels": False,
        "threshold_selection_on_iot_sfc_labels": False,
        "feature_selection_on_iot_sfc_labels": False,
        "model_selection_on_iot_sfc_labels": False,
        "score_only_after_license_schema_label_provenance_and_duplicate_checks": True,
        "unknown_or_unsupported_zeek_event_types": "BLOCK_NO_SILENT_ZERO_IMPUTATION",
        "ambiguous_attack_window_boundaries": "EXCLUDE_AND_REPORT_WITH_REASON",
        "missing_or_inconsistent_ground_truth": "BLOCK_AND_REQUIRE_INDEPENDENT_REVIEW",
        "minimum_test_policy": "one_frozen_model_one_fixed_threshold_all_eligible_records",
        "after_first_test_unblinding": "TARGET_BECOMES_EXPOSED_NO_RETRY_ACCEPTANCE",
        "if_any_gate_fails": "RESEARCH_NO_GO",
    })
    if analysis.get("slicing") != [
        "capture_utc_day", "attack_family", "benign_workload",
        "device_group_when_independently_grounded",
    ] or analysis.get("reporting") != [
        "TN_FP_FN_TP", "observed_FPR_and_recall", "wilson_95_bounds",
        "per_day_and_per_attack_family_support", "per_day_false_alert_burden",
        "duplicate_overlap_audit", "label_and_sensor_contract_audit",
    ]:
        raise ValueError("Analysis slicing/reporting was changed after preregistration")


def validate_archive_preflight(report: dict, spec: dict) -> None:
    """Verify the user-provided local ZIP metadata. NEVER open the target ZIP."""
    target = spec["target"]
    _require_fields(report, {
        "preflight_version": 1,
        "source_repository": target["zenodo_record"],
        "archive_basename": target["archive_basename"],
        "archive_bytes": TARGET_SIZE,
        "expected_archive_bytes": TARGET_SIZE,
        "expected_zenodo_md5": TARGET_MD5,
        "actual_md5": TARGET_MD5,
        "zenodo_md5_verified": True,
        "archive_sha256_computed_locally": TARGET_SHA,
        "member_count": 1,
        "declared_uncompressed_bytes": CSV_SIZE,
        "unsafe_paths": [],
        "duplicate_paths": [],
        "symlink_paths": [],
        "encrypted_entries": [],
        "member_paths_safe": True,
        "archive_listing_readable": True,
        "row_data_read": False,
        "csv_headers_read": False,
        "labels_inspected": False,
        "training_or_evaluation_performed": False,
        "member_crc_verified": False,
        "zip_member_payloads_integrity_verified": False,
        "model_frozen": False,
        "acceptance_status": "NOT_EVALUATED",
        "result": "ZIP_METADATA_PREFLIGHT_OK",
    })
    entries = report.get("zip_entries")
    if not isinstance(entries, list) or len(entries) != 1:
        raise ValueError("Expected exactly one CSV member in ZIP metadata")
    _require_fields(entries[0], {
        "path": target["single_csv_member"],
        "compressed_bytes": 776500529,
        "uncompressed_bytes": CSV_SIZE,
        "crc32_from_zip_directory": "df4767e0",
        "encrypted": False,
    })


def verify_model_bytes_and_manifest(model: Path, manifest_path: Path, spec: dict) -> dict:
    """Never call joblib.load: untrusted pickle execution is forbidden."""
    candidate = spec["model"]
    actual_sha = _sha256(model)
    if actual_sha != candidate["artifact_sha256"]:
        raise ValueError("Frozen model bytes do not match preregistered SHA")
    manifest = _json_object(manifest_path)
    _require_fields(manifest, {
        "artifact_sha256": MODEL_SHA,
        "research_model_sha256": MODEL_SHA,
        "bundle_protocol_sha256": MODEL_PROTOCOL_SHA,
        "protocol_sha256": MODEL_PROTOCOL_SHA,
        "model_frozen_from_exposed_training_only": True,
        "independent_test_performed": False,
        "production_signed": False,
        "operational_ml_acceptance": "NO_GO",
        "source_training_rows": 41670,
        "source_calibration_rows": 5026,
    })
    protocol = manifest["protocol"]
    _require_fields(protocol, {
        "feature_contract": FEATURE_CONTRACT,
        "threshold": 0.2,
        "unsw_original_zip_sha256":
            "3c7500f120405b21b44a2bf05134f49491f88a655ae3091fc1b269c4c9ece79a",
        "iot23_exposed_source_sha256":
            "7d1d052835439d77dae246b588d7628813bbdef21fdf3b323f4b3eb2c61ef146",
    })
    canonical = json.dumps(
        protocol, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if hashlib.sha256(canonical).hexdigest() != MODEL_PROTOCOL_SHA:
        raise ValueError("Frozen model protocol is not canonical/hash-pinned")
    selected = manifest["selected"]
    _require_fields(selected, {
        "cutoff": 0.2,
        "source_dev_only": True,
        "untouched_holdout_scored": False,
    })
    return {
        "model_sha256_verified": True,
        "manifest_protocol_sha256_verified": True,
        "trusted_model_deserialization_performed": False,
    }


def preflight(spec_path: Path, archive_report_path: Path,
              model_path: Path | None, manifest_path: Path | None) -> dict:
    spec = _json_object(spec_path)
    validate_preregistration(spec)
    validate_archive_preflight(_json_object(archive_report_path), spec)
    if (model_path is None) != (manifest_path is None):
        raise ValueError("Model and manifest must be supplied together")
    checks = {"model_sha256_verified": False, "manifest_protocol_sha256_verified": False}
    if model_path is not None and manifest_path is not None:
        checks = verify_model_bytes_and_manifest(model_path, manifest_path, spec)
    return {
        "status": ("PRE_SCORE_LOCK_VERIFIED" if checks["model_sha256_verified"]
                   else "PREREG_METADATA_VERIFIED_MODEL_BYTES_PENDING"),
        "protocol_id": spec["protocol_id"],
        "dataset_archive_sha256": TARGET_SHA,
        "model_sha256": MODEL_SHA,
        "decision_threshold": 0.2,
        "feature_contract": FEATURE_CONTRACT,
        "archive_checksum_origin": "user_local_preflight_report",
        "target_csv_opened": False,
        "labels_inspected": False,
        "training_or_scoring_performed": False,
        "license_and_ground_truth_review_pending": True,
        "independent_field_site": False,
        "operational_ml_acceptance": "NO_GO",
        **checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preregistration", type=Path, default=PROTOCOL)
    parser.add_argument("--archive-preflight", type=Path, required=True)
    parser.add_argument("--model", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists() or args.report.is_symlink():
        parser.error("Refusing to overwrite existing preregistration evidence")
    outcome = preflight(args.preregistration, args.archive_preflight, args.model, args.manifest)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as writer:
        json.dump(outcome, writer, sort_keys=True, indent=2)
        writer.write("\n")
        writer.flush()
        os.fsync(writer.fileno())
    print(json.dumps({
        "status": outcome["status"],
        "operational_ml_acceptance": "NO_GO",
        "target_csv_opened": False,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
