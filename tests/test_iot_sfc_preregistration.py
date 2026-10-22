"""No-target-content security tests for IoT-SFC v2 preregistration freeze."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from networkpulse.evaluation import iot_sfc_preregistration as p
from networkpulse.evaluation.v2_source_calibration import protocol as source_protocol


@pytest.fixture
def spec():
    value = json.loads(p.PROTOCOL.read_text(encoding="utf-8"))
    p.validate_preregistration(value)
    return value


@pytest.fixture
def archive_preflight(spec):
    """Exact prior ZIP *metadata* only; no CSV content in tests."""
    return {
        "preflight_version": 1,
        "source_repository": spec["target"]["zenodo_record"],
        "archive_basename": "iot_dataset_v7.zip",
        "archive_bytes": 776500807,
        "expected_archive_bytes": 776500807,
        "expected_zenodo_md5": p.TARGET_MD5,
        "actual_md5": p.TARGET_MD5,
        "zenodo_md5_verified": True,
        "archive_sha256_computed_locally": p.TARGET_SHA,
        "member_count": 1,
        "declared_uncompressed_bytes": p.CSV_SIZE,
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
        "zip_entries": [{
            "path": "iot_dataset_v7.csv",
            "compressed_bytes": 776500529,
            "uncompressed_bytes": p.CSV_SIZE,
            "crc32_from_zip_directory": "df4767e0",
            "encrypted": False,
        }],
    }


def _write_json(path: Path, obj):
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    return path


def test_preregistration_is_fixed_and_research_only(spec):
    assert spec["model"]["artifact_sha256"] == p.MODEL_SHA
    assert spec["model"]["threshold"] == 0.2
    assert spec["operational_ml_acceptance"] == "NO_GO"
    assert spec["target"]["license_and_permitted_use_verified"] is False
    assert spec["target"]["label_or_header_cells_inspected"] is False
    assert spec["numeric_gates"]["require_cluster_aware_uncertainty_review"] is True


@pytest.mark.parametrize("category,key,value", [
    ("model", "threshold", 0.21),
    ("model", "artifact_sha256", "f" * 64),
    ("model", "production_signed", True),
    ("target", "archive_sha256", "0" * 64),
    ("target", "label_or_header_cells_inspected", True),
    ("target", "independently_operated_field_site", True),
    ("target", "license_and_permitted_use_verified", True),
    ("numeric_gates", "fpr_wilson_95_upper_max", 0.06),
    ("numeric_gates", "recall_wilson_95_lower_min", 0.7),
    ("numeric_gates", "min_natural_attack", 1),
    ("frozen_analysis_plan", "training_on_iot_sfc_labels", True),
])
def test_any_regression_or_relabeling_is_rejected(spec, category, key, value):
    broken = copy.deepcopy(spec)
    broken[category][key] = value
    with pytest.raises(ValueError):
        p.validate_preregistration(broken)


def test_archive_preflight_accepts_only_metadata_only_lock(spec, archive_preflight):
    p.validate_archive_preflight(archive_preflight, spec)
    assert archive_preflight["labels_inspected"] is False


@pytest.mark.parametrize("key,value", [
    ("archive_sha256_computed_locally", "0" * 64),
    ("actual_md5", "0" * 32),
    ("member_crc_verified", True),
    ("csv_headers_read", True),
    ("labels_inspected", True),
    ("member_count", 2),
    ("unsafe_paths", ["../wrong.csv"]),
    ("acceptance_status", "PASS"),
])
def test_modified_archive_metadata_fails_closed(spec, archive_preflight, key, value):
    bad = copy.deepcopy(archive_preflight)
    bad[key] = value
    with pytest.raises(ValueError):
        p.validate_archive_preflight(bad, spec)


def test_member_path_identity_locked(spec, archive_preflight):
    wrong = copy.deepcopy(archive_preflight)
    wrong["zip_entries"][0]["path"] = "conn.log"
    with pytest.raises(ValueError):
        p.validate_archive_preflight(wrong, spec)


def test_preflight_without_model_has_no_frozen_model_claim(
    spec, archive_preflight, tmp_path,
):
    specs = _write_json(tmp_path / "spec.json", spec)
    report = _write_json(tmp_path / "archive.json", archive_preflight)
    outcome = p.preflight(specs, report, None, None)
    assert outcome["status"] == "PREREG_METADATA_VERIFIED_MODEL_BYTES_PENDING"
    assert outcome["model_sha256_verified"] is False
    assert outcome["target_csv_opened"] is False
    assert outcome["training_or_scoring_performed"] is False
    assert outcome["operational_ml_acceptance"] == "NO_GO"


def test_missing_pair_is_rejected(spec, archive_preflight, tmp_path):
    specs = _write_json(tmp_path / "spec.json", spec)
    report = _write_json(tmp_path / "archive.json", archive_preflight)
    with pytest.raises(ValueError, match="together"):
        p.preflight(specs, report, tmp_path / "model.joblib", None)


def _sample_manifest():
    actual_proto = source_protocol()
    actual_proto["threshold"] = 0.2
    sha = hashlib.sha256(json.dumps(
        actual_proto, sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    assert sha == p.MODEL_PROTOCOL_SHA
    return {
        "artifact_sha256": p.MODEL_SHA,
        "research_model_sha256": p.MODEL_SHA,
        "bundle_protocol_sha256": sha,
        "protocol_sha256": sha,
        "model_frozen_from_exposed_training_only": True,
        "independent_test_performed": False,
        "production_signed": False,
        "operational_ml_acceptance": "NO_GO",
        "source_training_rows": 41670,
        "source_calibration_rows": 5026,
        "protocol": actual_proto,
        "selected": {
            "cutoff": 0.2,
            "source_dev_only": True,
            "untouched_holdout_scored": False,
        },
    }


def test_manifest_protocol_validation_without_pickle_execution(spec, monkeypatch, tmp_path):
    manifest = _write_json(tmp_path / "model.json", _sample_manifest())
    dummy = tmp_path / "model.joblib"
    dummy.write_bytes(b"test only; never deserialize")
    # Stub only binary identity for unit coverage. Real bytes must be SHA checked.
    monkeypatch.setattr(p, "_sha256", lambda *_: p.MODEL_SHA)
    result = p.verify_model_bytes_and_manifest(dummy, manifest, spec)
    assert result["model_sha256_verified"]
    assert result["manifest_protocol_sha256_verified"]
    assert not result["trusted_model_deserialization_performed"]


def test_real_binary_sha_check_fails_on_fake_pickle(spec, tmp_path):
    dummy = tmp_path / "model.joblib"
    dummy.write_bytes(b"untrusted")
    manifest = _write_json(tmp_path / "model.json", _sample_manifest())
    with pytest.raises(ValueError, match="SHA"):
        p.verify_model_bytes_and_manifest(dummy, manifest, spec)


def test_manifest_protocol_tampering_rejected(spec, monkeypatch, tmp_path):
    manifest = _sample_manifest()
    manifest["protocol"]["estimator"]["max_depth"] = 99
    target = _write_json(tmp_path / "manifest.json", manifest)
    dummy = tmp_path / "model.joblib"
    dummy.write_bytes(b"not a model")
    monkeypatch.setattr(p, "_sha256", lambda *_: p.MODEL_SHA)
    with pytest.raises(ValueError, match="canonical/hash-pinned"):
        p.verify_model_bytes_and_manifest(dummy, target, spec)


def test_metadata_loader_refuses_symlink(tmp_path):
    original = _write_json(tmp_path / "real.json", {"x": 1})
    alias = tmp_path / "alias.json"
    alias.symlink_to(original)
    with pytest.raises(ValueError, match="symlink"):
        p._json_object(alias)
