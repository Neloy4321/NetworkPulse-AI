"""No fabricated cross-domain outcome: source-train V2 freeze regression."""
from pathlib import Path

import pytest

from networkpulse.evaluation.v2_mixed_source_freeze import (
    ESTIMATOR, FIXED_CUTOFF, PROTOCOL, fit, freeze,
    load_real_iot23, load_real_unsw, protocol_digest,
)
from networkpulse.feature_contract_v2 import V2_FEATURE_CONTRACT


def test_mixed_development_training_protocol_is_locked():
    assert PROTOCOL["feature_contract"] == V2_FEATURE_CONTRACT
    assert PROTOCOL["source_families"] == ["UNSW-NB15", "IoT-23v2"]
    assert PROTOCOL["iot23v2_rows"] == 23145
    assert PROTOCOL["training_domains"] == "previously_exposed_development_data_only"
    assert ESTIMATOR["random_state"] == 42
    assert ESTIMATOR["n_estimators"] == 160
    assert FIXED_CUTOFF == 0.5
    assert PROTOCOL["new_production_model_approved"] is False
    assert len(protocol_digest()) == 64


def test_unauthorized_or_mutated_source_archive_rejected(tmp_path: Path):
    invalid = tmp_path / "bad_source.zip"
    invalid.write_bytes(b"not authentic")
    with pytest.raises(ValueError, match="SHA or size mismatch"):
        load_real_unsw(invalid)


def test_mutated_iot23_capture_refused_for_training(tmp_path: Path):
    invalid = tmp_path / "fake_iot23.labeled"
    invalid.write_bytes(b"fake zeek content")
    with pytest.raises(ValueError, match="SHA or size mismatch"):
        load_real_iot23(invalid)


def test_experiment_refuses_missing_source_family():
    with pytest.raises(ValueError, match="missing one exposed development"):
        fit([], [])


def test_freeze_does_not_overwrite_existing_model(tmp_path: Path):
    output = tmp_path / "frozen.joblib"
    output.write_text("old")
    with pytest.raises(ValueError, match="refuse overwriting"):
        freeze(tmp_path / "unsw.zip", tmp_path / "iot.labeled",
               output, tmp_path / "manifest.json")


def test_v2_training_workflow_never_reports_independent_ml_acceptance():
    workflow = (Path(__file__).resolve().parents[1] /
                ".github/workflows/v2-mixed-source-freeze.yml").read_text("utf-8")
    assert "v2_mixed_source_freeze" in workflow
    assert "research-v2-model" in workflow
    assert "independent_test_performed" in workflow
    assert "R2_SECRET_ACCESS_KEY" in workflow
    assert "active-production-release" not in workflow
