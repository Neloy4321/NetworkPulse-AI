"""Prospective source and artifact protections; synthetic fixture tests only."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
import sklearn

from networkpulse.evaluation.frozen_rf_research import (
    SELECTED, RESEARCH_CONTRACT, protocol_sha256,
    private_ledger_bytes, write_private_training_ledger,
)
from networkpulse.evaluation.prospective_external_rf import (
    evaluate, read_verified_canonical, validate_target_attestation,
)
from networkpulse.evaluation.source_only_candidates import (
    ESTIMATOR, FIXED_CUTOFF, candidate_features,
)
from networkpulse.evaluation.unsw_to_toniot import UNSW_SHA, digest
from networkpulse.schemas import FlowEvent


def fake(i, label: str) -> FlowEvent:
    return FlowEvent(
        timestamp=datetime.fromtimestamp(1500000000 + i, tz=timezone.utc),
        source="canonical",
        src_ip="192.0.2.10", dst_ip="198.51.100.23",
        src_port=40000 + i, dst_port=443, proto="tcp",
        duration=2 + i % 10, orig_bytes=100 + i,
        resp_bytes=600 + 2 * i, orig_pkts=3 + i % 10,
        resp_pkts=12 + i % 15, conn_state="sf", label=label,
    )


def attest(expected):
    return {
        "schema_version": 1,
        "dataset_family": "new_authorized_network_from_separate_organization",
        "source_operator": "Authorized lab test operator",
        "authorization_reference": "private-operator-approval-ref",
        "label_review_method": "independent review of test session labeling",
        "native_sensor_contract": "documented canonical flow JSONL",
        "site_provenance_kind": "separate_laboratory",
        "capture_period_utc": "2017-07-14 to 2017-07-15 UTC",
        "pre_registration_reference": "private-protocol-version-1",
        "canonical_jsonl_sha256": expected,
        "labels_are_independently_adjudicated": True,
        "reviewer_confirmed_frozen_model_before_target": True,
    }


def prepare_files(tmp_path):
    training = [fake(i, "anomaly" if i >= 4 else "benign") for i in range(8)]
    vectorizer = DictVectorizer(sparse=False)
    x = vectorizer.fit_transform([candidate_features(e, SELECTED) for e in training])
    estimator = RandomForestClassifier(**ESTIMATOR).fit(x, [0]*4+[1]*4)
    bundle = {
        "schema_version": 1, "research_only": True,
        "production_approved": False,
        "feature_contract": RESEARCH_CONTRACT,
        "research_candidate": SELECTED,
        "feature_count": x.shape[1],
        "source_sha256": UNSW_SHA,
        "protocol_sha256": protocol_sha256(),
        "fixed_cutoff": FIXED_CUTOFF,
        "sklearn_version": sklearn.__version__,
        "vectorizer": vectorizer, "estimator": estimator,
    }
    ledger_path = tmp_path / "private-training-ledger.tsv"
    ledger_sha = write_private_training_ledger(
        ledger_path, private_ledger_bytes(training)
    )
    model_path = tmp_path / "model.joblib"
    joblib.dump(bundle, model_path)
    checksum = digest(model_path)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({
        "status": "source_only_supervised_research_bundle_frozen",
        "bundle_sha256": checksum,
        "source_zip_sha256": UNSW_SHA,
        "protocol_sha256": protocol_sha256(),
        "production_approved": False,
        "operator_signed": False,
        "training_ledger_sha256": ledger_sha,
        "training_unique": len(training),
    }))
    source_path = tmp_path / "labeled-canonical.jsonl"
    source_path.write_text("\n".join(
        fake(i+100, "anomaly" if i >= 210 else "benign").model_dump_json()
        for i in range(340)
    ) + "\n")
    att_path = tmp_path / "attestation.json"
    att_path.write_text(json.dumps(attest(digest(source_path))))
    return model_path, manifest_path, source_path, att_path, checksum


def evaluate_fixture(tmp_path, **changes):
    model, manifest, target, att, expected = prepare_files(tmp_path)
    values = {
        "trusted_bundle_path": model,
        "manifest_path": manifest,
        "expected_bundle_sha256": expected,
        "canonical_labeled_path": target,
        "expected_target_sha256": digest(target),
        "source_attestation_path": att,
        "private_training_ledger_path": tmp_path / "private-training-ledger.tsv",
    }
    values.update(changes)
    return evaluate(**values)


def test_no_external_research_result_is_ever_production_acceptance(tmp_path: Path):
    report = evaluate_fixture(tmp_path)
    assert report["status"] == "prospective_external_research_numeric_measurement_only"
    assert report["operational_ml_acceptance_demonstrated"] is False
    assert report["production_deployment_verified"] is False
    assert report["active_signed_artifact_equivalence_verified"] is False
    assert report["training_test_cross_dataset_overlap_audited"] is True
    assert report["training_ids_overlap"] == 0
    assert report["normalized_flow_overlap"] == 0
    assert report["source_provenance"]["site_independence_verified"] is False
    assert report["target_unique_rows"] == 340
    assert report["evaluation"]["benign"] == 210
    assert report["evaluation"]["attack"] == 130
    assert "192.0.2." not in json.dumps(report)
    assert "198.51.100." not in json.dumps(report)


def test_tampering_model_detected_before_pickle_load(tmp_path: Path):
    model, manifest, target, att, expected = prepare_files(tmp_path)
    with model.open("ab") as h:
        h.write(b"untrusted")
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        evaluate(trusted_bundle_path=model, manifest_path=manifest,
                 expected_bundle_sha256=expected,
                 canonical_labeled_path=target,
                 expected_target_sha256=digest(target),
                 source_attestation_path=att,
                 private_training_ledger_path=tmp_path / "private-training-ledger.tsv")


def test_attestation_required_and_exposed_dataset_family_blocked(tmp_path: Path):
    model, manifest, target, att, expected = prepare_files(tmp_path)
    bad = attest(digest(target))
    bad["dataset_family"] = "unsw-nb15"
    with pytest.raises(ValueError, match="previously exposed"):
        validate_target_attestation(bad, target_sha256=digest(target))
    bad = attest(digest(target))
    bad["labels_are_independently_adjudicated"] = False
    with pytest.raises(ValueError, match="genuine labels"):
        validate_target_attestation(bad, target_sha256=digest(target))
    bad = attest(digest(target))
    bad["reviewer_confirmed_frozen_model_before_target"] = False
    with pytest.raises(ValueError, match="frozen before"):
        validate_target_attestation(bad, target_sha256=digest(target))


def test_bad_label_and_source_hashes_are_rejected(tmp_path: Path):
    model, manifest, target, att, expected = prepare_files(tmp_path)
    with pytest.raises(ValueError, match="SHA256 changed"):
        read_verified_canonical(target, "f" * 64)
    rows = target.read_text().splitlines()
    changed = json.loads(rows[3])
    changed["label"] = None
    rows[3] = json.dumps(changed)
    target.write_text("\n".join(rows) + "\n")
    with pytest.raises(ValueError, match="unlabeled"):
        read_verified_canonical(target, digest(target))


def test_identical_duplicate_flow_does_not_count_twice(tmp_path: Path):
    model, manifest, target, att, expected = prepare_files(tmp_path)
    lines = target.read_text().splitlines()
    target.write_text("\n".join(lines + [lines[0]]) + "\n")
    rows, duplicates = read_verified_canonical(target, digest(target))
    assert len(rows) == 340
    assert duplicates == 1


def test_source_file_does_not_implicitly_access_ton_or_accept_unpinned_pickle():
    path = (Path(__file__).resolve().parents[1] /
            "networkpulse/evaluation/prospective_external_rf.py").read_text("utf-8")
    assert "verify_bundle_checksum" in path
    assert "joblib.load" in path
    assert "ton-source.zip" not in path
    assert "production_deployment_verified" in path


def test_source_fit_ledger_is_required_and_overlap_rejected(tmp_path: Path):
    model, manifest, target, att, expected = prepare_files(tmp_path)
    original = tmp_path / "private-training-ledger.tsv"
    original.unlink()
    with pytest.raises((FileNotFoundError, ValueError)):
        evaluate(
            trusted_bundle_path=model, manifest_path=manifest,
            expected_bundle_sha256=expected, canonical_labeled_path=target,
            expected_target_sha256=digest(target),
            source_attestation_path=att,
            private_training_ledger_path=original,
        )


def test_reused_training_flow_in_prospective_target_is_rejected(tmp_path: Path):
    model, manifest, target, att, expected = prepare_files(tmp_path)
    rows = target.read_text().splitlines()
    rows[0] = fake(0, "benign").model_dump_json()
    target.write_text("\n".join(rows) + "\n")
    att.write_text(json.dumps(attest(digest(target))))
    with pytest.raises(ValueError, match="overlaps prospective holdout"):
        evaluate(
            trusted_bundle_path=model, manifest_path=manifest,
            expected_bundle_sha256=expected, canonical_labeled_path=target,
            expected_target_sha256=digest(target),
            source_attestation_path=att,
            private_training_ledger_path=tmp_path / "private-training-ledger.tsv",
        )
