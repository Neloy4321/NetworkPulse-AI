from types import SimpleNamespace

import numpy as np
import pytest

from networkpulse.detector import Detector, train
from networkpulse.reliability import (
    calibration_diagnostics, confusion_profile, reliability_slices,
    wilson_upper_bound,
)
from networkpulse.simulator import sample_flows


def test_wilson_upper_boundary_counts_and_fpr():
    assert 0 < wilson_upper_bound(0, 100) < .04
    assert wilson_upper_bound(100, 100) == 1.0
    with pytest.raises(ValueError):
        wilson_upper_bound(1, 0)
    with pytest.raises(ValueError):
        wilson_upper_bound(3, 2)
    data = confusion_profile([0, 0, 0, 1, 1], [0, 1, 1, 1, 0])
    assert data["false_positive_rate"] == pytest.approx(2/3, abs=1e-6)
    assert data["confusion_matrix"] == {"tn": 1, "fp": 2, "fn": 1, "tp": 1}
    assert data["fpr_wilson_upper_95_one_sided"] >= 2 / 3
    assert confusion_profile([1, 1], [0, 1])["false_positive_rate"] is None


def test_calibration_ignores_heldout_labels_and_rejects_nonfinite():
    c = calibration_diagnostics(np.linspace(-.3, .4, 50))
    assert c["count"] == 50
    assert float(c["quantiles"]["0.99"]["threshold"]) > float(c["quantiles"]["0.95"]["threshold"])
    with pytest.raises(ValueError):
        calibration_diagnostics([float("nan")] * 30)
    with pytest.raises(ValueError):
        confusion_profile([0, 2], [0, 1])


def test_explanations_are_model_score_sensitivities_without_raw_ips(tmp_path):
    sample = sample_flows(310, seed=13)
    trained = train(sample, seed=13)
    assert trained.metadata["metrics"]["benign_count"] > 0
    assert trained.metadata["metrics"]["fpr_wilson_upper_95_one_sided"] is not None
    assert "calibration_diagnostics" in trained.metadata
    assert "slices" in trained.metadata["metrics"]
    explanations = trained.sensitivity_explanations(sample[-4:], top_k=4)
    assert len(explanations) == 4
    assert explanations[0]["sensitivity_type"] == "one_feature_replaced_by_benign_training_median"
    assert all("src_ip" not in str(item) for item in explanations)
    assert all(all(row["score_delta"] > 0 for row in item["increasing_anomaly_score"])
               for item in explanations)
    restored = tmp_path/"model.joblib"
    trained.save(restored)
    assert Detector.load(restored).sensitivity_explanations(sample[-4:]) == trained.sensitivity_explanations(sample[-4:])
    with pytest.raises(ValueError, match="25"):
        trained.sensitivity_explanations(sample[-26:])


def test_slices_withhold_unstable_rate():
    events = sample_flows(120, seed=22)
    predicted = [SimpleNamespace(anomalous=i % 11 == 0) for i in range(len(events))]
    report = reliability_slices(events, predicted, min_benign=100)
    assert "sensor" in report["slices"]
    assert any(item.get("withheld_reason") for groups in report["slices"].values()
               for item in groups.values())
    with pytest.raises(ValueError):
        reliability_slices(events, predicted[:-1])
