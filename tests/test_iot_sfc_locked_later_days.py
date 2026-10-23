"""Safe tests for April15-17 post-lock same-lab generalization experiment."""
from __future__ import annotations

from collections import Counter
from datetime import date

import pytest

from networkpulse.evaluation import iot_sfc_locked_later_days as stage


def test_candidate_model_lock_and_no_threshold_retune():
    assert stage.MODEL_SHA == (
        "ecc320bc693481fc45b143b48ffbebcb117899e888e4687930f3361501af6fa1"
    )
    assert stage.CUTOFF == 0.9
    assert stage.FIT_DEV_PREFIX_EXCLUDED == 450000
    assert stage.TEST_DAYS == (
        date(2025, 4, 15), date(2025, 4, 16), date(2025, 4, 17)
    )
    assert stage.MAX_PER_DAY == 60000
    assert stage.SCAN_ROWS_AFTER_PREFIX == 9000000


def test_actual_flow_confusion_calculated_and_not_auto_acceptance():
    m = stage.summarize_confusion(
        Counter({"tn": 2000, "fp": 10, "fn": 200, "tp": 800})
    )
    assert m["benign"] == 2010
    assert m["attack"] == 1000
    assert m["confusion"] == {"tn": 2000, "fp": 10, "fn": 200, "tp": 800}
    assert m["fpr_wilson_upper95"] < 0.05
    assert m["recall_wilson_lower95"] < 0.8
    assert not m["numerical_gates_descriptively_met"]
    assert not m["independent_ground_truth"]
    assert not m["external_field_acceptance"]


def test_both_numeric_gates_must_hold_jointly():
    passing = stage.summarize_confusion(
        Counter({"tn": 2000, "fp": 0, "fn": 0, "tp": 2000})
    )
    assert passing["numerical_gates_descriptively_met"] is True
    assert passing["external_field_acceptance"] is False


def test_no_attack_or_benign_support_never_faked():
    benign_only = stage.summarize_confusion(Counter({"tn": 400}))
    assert benign_only["recall"] is None
    assert benign_only["recall_wilson_lower95"] is None
    assert not benign_only["numerical_gates_descriptively_met"]
    attack_only = stage.summarize_confusion(Counter({"tp": 400}))
    assert attack_only["fpr"] is None
    assert attack_only["fpr_wilson_upper95"] is None
    assert not attack_only["numerical_gates_descriptively_met"]


def test_archive_hash_verification_runs_before_untrusted_pickle(monkeypatch, tmp_path):
    file = tmp_path / "unsigned-research-day-fenced.joblib"
    file.write_bytes(b"something untrusted")
    source = tmp_path / "iot_dataset_v7.zip"
    source.write_bytes(b"not original data")
    with pytest.raises(ValueError, match="Source name/size"):
        stage.verify_source_and_model(source, file)


def test_source_and_candidate_digest_must_match_even_when_size_is_forged(
    monkeypatch, tmp_path,
):
    source = tmp_path / "iot_dataset_v7.zip"
    source.write_bytes(b"x")
    model = tmp_path / "research.joblib"
    model.write_bytes(b"not real")
    monkeypatch.setattr(stage, "TARGET_SIZE", 1)
    with pytest.raises(ValueError, match="SHA mismatch"):
        stage.verify_source_and_model(source, model)
