"""Predeclaration and holdout safeguards; synthetic unit fixtures only."""
from pathlib import Path

import numpy as np
import pytest

from networkpulse.evaluation.v2_calibrated_new_lab_eval import (
    CAPTURES, CUTOFF, FROZEN_MODEL_SHA256, bin_metrics, evaluate,
)


def test_exact_model_and_new_targets_locked():
    assert FROZEN_MODEL_SHA256 == (
        "cd239783fd4318c0c4e897f1d451c2d5af4b42132979c79a4e489df626f538a5"
    )
    assert CUTOFF == 0.2
    assert list(CAPTURES) == [
        "CTU-IoT-Malware-Capture-42-1", "CTU-Honeypot-Capture-4-1"
    ]


def test_natural_class_support_never_fabricated():
    labels = np.array([0]*100 + [1]*12)
    pred = np.array([False]*112)
    result = bin_metrics(labels,pred)
    assert result["status"] == "BLOCKED_INSUFFICIENT_NATURAL_CLASS_SUPPORT"
    assert result["numeric_research_pass"] is False
    assert result["fpr_upper_95"] is None
    assert result["recall_lower_95"] is None


def test_low_fpr_high_recall_computed_from_natural_flow_counts():
    labels = np.array([0]*800 + [1]*400)
    pred = np.array([False]*792 + [True]*8 +
                    [False]*8 + [True]*392)
    outcome = bin_metrics(labels,pred)
    assert outcome["confusion"] == {"tn":792,"fp":8,"fn":8,"tp":392}
    assert outcome["numeric_research_pass"] is True


def test_high_fpr_or_bad_recall_cannot_pass_quality():
    labels = np.array([0]*800 + [1]*400)
    false_alarm = np.array([True]*100 + [False]*700 +
                           [True]*390 + [False]*10)
    assert bin_metrics(labels,false_alarm)["numeric_research_pass"] is False
    poor_recall = np.array([False]*800 + [True]*290 + [False]*110)
    assert bin_metrics(labels,poor_recall)["numeric_research_pass"] is False


def test_unregistered_targets_fail_before_any_model_loading(tmp_path:Path):
    with pytest.raises(ValueError,match="Both fixed"):
        evaluate(tmp_path/"no-model.joblib",tmp_path/"manifest.json",{})
    invalid={name:tmp_path/filename for name,filename in CAPTURES.items()}
    with pytest.raises((FileNotFoundError,ValueError)):
        evaluate(tmp_path/"no-model.joblib",tmp_path/"manifest.json",invalid)


def test_candidate_repository_declares_no_real_approval():
    import inspect
    from networkpulse.evaluation import v2_calibrated_new_lab_eval as mod
    body=inspect.getsource(mod)
    assert '"p0_operational_ml_acceptance": "NO_GO"' in body
    assert "target_labels_used_to_fit_tune_or_choose_threshold" in body
    assert "same_iot23_laboratory_family_as_source_training" in body
