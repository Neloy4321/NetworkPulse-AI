"""Fail-closed frozen research candidate acceptance-readiness unit tests."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
import sklearn
import numpy as np

from networkpulse.evaluation.frozen_rf_research import (
    SELECTED, RESEARCH_CONTRACT, RESEARCH_BUNDLE_SCHEMA,
    fixed_protocol, protocol_sha256, score_verified_bundle,
    validate_loco_result, verify_bundle_checksum, fit_from_approved_source,
    private_ledger_bytes, write_private_training_ledger,
)
from networkpulse.evaluation.source_only_candidates import (
    CANDIDATES, ESTIMATOR, FIXED_CUTOFF, candidate_features,
)
from networkpulse.evaluation.source_only_loco import MEMBERS
from networkpulse.evaluation.unsw_to_toniot import UNSW_SHA, digest
from networkpulse.schemas import FlowEvent


def event(i: int, label="benign") -> FlowEvent:
    return FlowEvent(
        timestamp=datetime.fromtimestamp(1450000000 + i, tz=timezone.utc),
        source="canonical", src_ip="198.51.100.11",
        dst_ip="203.0.113.19", src_port=20500 + i,
        dst_port=443 + i, proto="tcp", duration=float(i + 1),
        orig_bytes=100 + i, resp_bytes=200 + i,
        orig_pkts=10 + i, resp_pkts=20 + i,
        conn_state="sf", label=label,
    )


def fake_bundle():
    training = [event(i, "anomaly" if i >= 4 else "benign") for i in range(8)]
    vec = DictVectorizer(sparse=False)
    x = vec.fit_transform([candidate_features(e, SELECTED) for e in training])
    model = RandomForestClassifier(**ESTIMATOR)
    model.fit(x, np.array([0] * 4 + [1] * 4))
    return {
        "schema_version": RESEARCH_BUNDLE_SCHEMA,
        "research_only": True, "production_approved": False,
        "feature_contract": RESEARCH_CONTRACT,
        "research_candidate": SELECTED, "feature_count": x.shape[1],
        "source_sha256": UNSW_SHA,
        "protocol_sha256": protocol_sha256(),
        "fixed_cutoff": FIXED_CUTOFF,
        "sklearn_version": sklearn.__version__,
        "vectorizer": vec, "estimator": model,
    }


def fake_loco():
    return {
        "status": "exposed_source_loco_research_completed",
        "operational_acceptance_demonstrated": False,
        "independent_site_verified": False,
        "automatic_winner_selected": False,
        "protocol": {"source_sha256": UNSW_SHA},
        "folds": [
            {"excluded_capture": member,
             "status": "measured_exposed_source_capture_development_only",
             "models": {
                 selected: {
                     "status": "measured_same_source_cross_capture_not_acceptance",
                     "research_numeric_thresholds_met": True,
                     "class_counts": {"benign": 500, "anomaly": 200},
                 } for selected in CANDIDATES
             }} for member in MEMBERS
        ],
    }


def test_predeclared_freeze_has_deterministic_provenance_and_only_research_scope():
    protocol = fixed_protocol()
    assert protocol["research_selected_candidate"] == SELECTED
    assert protocol["training_scope"] == "all_four_exposed_UNSW_capture_samples"
    assert protocol["fixed_cutoff"] == 0.5
    assert len(protocol_sha256()) == 64
    assert "TON" not in str(protocol)
    assert protocol["production_feature_version_unchanged"] == 1


def test_cannot_freeze_with_missing_or_failed_legacy_source_fold():
    valid = fake_loco()
    validate_loco_result(valid)
    broken = copy.deepcopy(valid)
    broken["folds"][2]["models"][SELECTED]["research_numeric_thresholds_met"] = False
    with pytest.raises(ValueError, match="gates not demonstrated"):
        validate_loco_result(broken)
    broken = copy.deepcopy(valid)
    broken["folds"].pop()
    with pytest.raises(ValueError, match="missing"):
        validate_loco_result(broken)


def test_label_or_artificial_external_data_cannot_approve_freeze():
    broken = fake_loco()
    broken["independent_site_verified"] = True
    with pytest.raises(ValueError, match="misrepresents"):
        validate_loco_result(broken)
    broken = fake_loco()
    broken["protocol"]["source_sha256"] = "b" * 64
    with pytest.raises(ValueError, match="checksum mismatch"):
        validate_loco_result(broken)


def test_source_sha_lock_and_modified_artifact_detected_without_unpickling(tmp_path: Path):
    path = tmp_path / "candidate.joblib"
    joblib.dump(fake_bundle(), path)
    expected = digest(path)
    assert verify_bundle_checksum(path, expected) == expected
    with path.open("ab") as out:
        out.write(b"tamper")
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        verify_bundle_checksum(path, expected)
    with pytest.raises(ValueError, match="out-of-band"):
        verify_bundle_checksum(path, "not_sha")


def test_serialized_local_candidate_has_deterministic_prediction_parity(tmp_path: Path):
    bundle = fake_bundle()
    path = tmp_path / "locally-created.joblib"
    joblib.dump(bundle, path)
    verify_bundle_checksum(path, digest(path))
    restored = joblib.load(path)  # This is locally generated test fixture only.
    events = [event(1), event(6, "anomaly")]
    original = score_verified_bundle(bundle, events)
    loaded = score_verified_bundle(restored, events)
    assert np.array_equal(original, loaded)
    assert (loaded >= 0).all() and (loaded <= 1).all()


def test_unknown_feature_or_version_contract_rejected():
    bundle = fake_bundle()
    bundle["production_approved"] = True
    with pytest.raises(ValueError, match="mismatch"):
        score_verified_bundle(bundle, [event(1)])
    bundle = fake_bundle()
    bundle["research_candidate"] = "random_unregistered"
    with pytest.raises(ValueError, match="mismatch"):
        score_verified_bundle(bundle, [event(1)])


def test_only_authentic_pinned_zip_can_be_used(tmp_path: Path):
    wrong = tmp_path / "unsw.zip"
    wrong.write_bytes(b"fake ZIP")
    with pytest.raises(ValueError, match="length or SHA256"):
        fit_from_approved_source(wrong)


def test_workflow_requires_model_hash_before_external_promotion():
    text = (Path(__file__).resolve().parents[1] /
            ".github/workflows/source-only-feature-audit.yml").read_text("utf-8")
    assert "networkpulse.evaluation.frozen_rf_research" in text
    assert "frozen-source-rf-research-only.joblib" in text
    assert "frozen-source-rf-manifest.json" in text


def test_restricted_source_training_ledger_is_deterministic_and_mode_0600(tmp_path: Path):
    rows = [event(i, "anomaly" if i % 2 else "benign") for i in range(8)]
    content = private_ledger_bytes(rows)
    assert content == private_ledger_bytes(list(reversed(rows)))
    assert b"198.51.100." not in content
    assert b"203.0.113." not in content
    output = tmp_path / "private-source-training-ledger.tsv"
    digest_saved = write_private_training_ledger(output, content)
    from networkpulse.generalization_evidence import load_training_keys
    imported = load_training_keys(output, digest_saved)
    assert len(imported.canonical_ids) == 8
    assert len(imported.normalized_fingerprints) == 8
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="already exists"):
        write_private_training_ledger(output, content)


def test_verified_source_training_ledger_rebuild_requires_manifest(tmp_path: Path):
    from networkpulse.evaluation.source_training_ledger import rebuild
    fake_source = tmp_path / "source.zip"
    fake_source.write_bytes(b"source-not-authorized")
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"status":"source_only_supervised_research_bundle_frozen"}')
    with pytest.raises(ValueError, match="manifest mismatch"):
        rebuild(fake_source, manifest, tmp_path / "ledger.tsv")
