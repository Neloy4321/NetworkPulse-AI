import pytest

from networkpulse.detector import Detector, train
from networkpulse.features import event_features, explain
from networkpulse.simulator import sample_flows


def test_temporal_holdout_and_reproducibility():
    events = sample_flows(400, seed=21)
    m1 = train(events, seed=21)
    m2 = train(list(reversed(events)), seed=21)
    assert m1.threshold == pytest.approx(m2.threshold)
    assert m1.metadata["train_count"] == 240
    assert m1.metadata["cal_count"] == 60
    assert m1.metadata["holdout_count"] == 100
    assert "f1" in m1.metadata["metrics"]


def test_scoring_roundtrip(trained_detector, samples, tmp_path):
    path = tmp_path / "model.joblib"
    trained_detector.save(path)
    restored = Detector.load(path)
    orig = trained_detector.score(samples[-20:])
    new = restored.score(samples[-20:])
    assert [x.anomalous for x in orig] == [x.anomalous for x in new]
    assert [x.risk for x in orig] == [x.risk for x in new]


def test_model_guards(samples):
    with pytest.raises(ValueError, match="quantile"):
        train(samples, quantile=0.4)
    with pytest.raises(ValueError, match="at least 100"):
        train(samples[:20])


def test_feature_contract_and_explanatory_signals(samples):
    feats = event_features(samples[0])
    assert "log_bytes_per_second" in feats
    assert all(isinstance(x, str) for x in explain(samples[0]))


def test_non_empty_synthetic_holdout(trained_detector):
    metrics = trained_detector.metadata["metrics"]
    assert metrics["holdout_anomalies"] > 0
    assert 0 <= metrics["precision"] <= 1
    assert 0 <= metrics["recall"] <= 1
