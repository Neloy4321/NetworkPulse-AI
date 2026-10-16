"""Safety regression tests only; no true IoT-23 source loaded in unit CI."""
from pathlib import Path
import pytest
from networkpulse.evaluation.iot23v2_exact_runtime_recheck import (
    FROZEN_RF_SHA256, SOURCE_SHA256, SOURCE_BYTES, run,
)


def test_pinned_original_uploaded_source_and_frozen_bundle_are_immutable():
    assert SOURCE_BYTES == 3019311
    assert SOURCE_SHA256 == (
        "7d1d052835439d77dae246b588d7628813bbdef21fdf3b323f4b3eb2c61ef146"
    )
    assert FROZEN_RF_SHA256 == (
        "ba5fbc2cb171b0f79a31d99e71fbe438135325babc9d939d26c8589f66ff954b"
    )


def test_source_integrity_fails_before_model_load(tmp_path: Path):
    sample = tmp_path / "iot23v2.labeled"
    sample.write_bytes(b"fake malicious network data")
    with pytest.raises(ValueError, match="size/SHA256 mismatch"):
        run(sample, tmp_path / "model.joblib",
            tmp_path / "manifest.json", tmp_path / "ledger.tsv")


def test_model_integrity_fails_before_deserialization(tmp_path: Path):
    original = tmp_path / "captured.zeek"
    # Same nominal size, but known incorrect SHA -> refuse immediately.
    original.write_bytes(b"0" * SOURCE_BYTES)
    with pytest.raises(ValueError, match="size/SHA256 mismatch"):
        run(original, tmp_path / "model.joblib",
            tmp_path / "manifest.json", tmp_path / "ledger.tsv")


def test_source_runtime_recheck_declares_no_field_acceptance():
    source = (Path(__file__).resolve().parents[1] /
              "networkpulse/evaluation/iot23v2_exact_runtime_recheck.py").read_text()
    assert "source_exposed_to_analyst_before_exact_runtime_confirmation" in source
    assert '"numeric_research_gate": "passed" if numeric_pass else "failed"' in source
    assert '"production_ml_acceptance_demonstrated": False' in source
    assert '"training_flow_overlap": 0' in source
    assert "load_training_keys(" in source
    assert "source_missingness_report" in source
    assert "score_verified_bundle(" in source
    assert "SOURCE_SHA256" in source
