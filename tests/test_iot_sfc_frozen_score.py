"""Tests of frozen IoT-SFC source stem and exact metric/confusion handling."""

import numpy as np
import pytest

from networkpulse.evaluation import iot_sfc_frozen_score as score
from networkpulse.evaluation.iot_sfc_v7_conn_adapter import RowNotEligible
from networkpulse.feature_contract_v2 import features_v2


def fake_row(source_type="conn"):
    return {
        "log_type": source_type, "ts": "1743681600.0",
        "uid": "example", "orig_h": "192.0.2.10",
        "orig_p": "30000", "resp_h": "198.51.100.21",
        "resp_p": "53", "proto": "udp", "orig_bytes": "23",
        "resp_bytes": "-", "orig_pkts": "1", "resp_pkts": "-",
        "duration": "0.9", "conn_state": "SF",
        "attack": "1", "type_of_attack": "example",
        "label_source": "test-only", "window_id": "test-id",
    }


def test_short_conn_is_source_specific_and_preserves_zeek_feature_vector():
    row = fake_row()
    converted = score.adapt_v7_conn(row)
    assert converted.label is None
    assert converted.src_port == 30000
    assert converted.resp_bytes is None
    assert features_v2(converted)["missing_resp_bytes"] == 1.0
    assert features_v2(converted)["missing_resp_pkts"] == 1.0


@pytest.mark.parametrize("type_", ["dns", "http", "conn.log", "", "weird"])
def test_non_conn_sources_blocked(type_):
    with pytest.raises(RowNotEligible, match="not_v7_native_conn_stem"):
        score.adapt_v7_conn(fake_row(type_))


def test_descriptive_metrics_confusion_and_no_false_acceptance():
    from collections import Counter
    values = Counter({"tn": 100, "fp": 2, "fn": 2, "tp": 110})
    report = score._quality(values)
    assert report["confusion"] == {"tn": 100, "fp": 2, "fn": 2, "tp": 110}
    assert report["ground_truth_independently_adjudicated"] is False
    assert report["true_acceptance"] == "NOT_ESTABLISHED"
    assert "numeric_research_pass" not in report
    assert report["fpr_upper_95"] < 0.05
    assert report["recall_lower_95"] > 0.8


def test_one_class_returns_blocked_with_no_invented_confidence():
    from collections import Counter
    x = score._quality(Counter({"tn": 9}))
    assert x["fpr_upper_95"] is None
    assert x["recall_lower_95"] is None
    assert x["true_acceptance"] == "NOT_ESTABLISHED"


def test_batch_uses_unmodified_probabilities_and_threshold():
    from collections import Counter, defaultdict
    class Encoder:
        def transform(self, records):
            assert len(records) == 4
            return np.zeros((4, 1))
    class Estimator:
        def predict_proba(self, matrix):
            assert matrix.shape == (4, 1)
            return np.array([
                [0.9, 0.1], [0.8, 0.2],
                [0.9, 0.1], [0.79, 0.21],
            ])
    f = score.adapt_v7_conn(fake_row())
    total = Counter()
    days = defaultdict(Counter)
    score._batch({"vectorizer": Encoder(), "estimator": Estimator()},
                 [f] * 4, [0, 0, 1, 1], ["a", "a", "b", "b"], total, days)
    assert total == {"tn": 1, "fp": 1, "fn": 1, "tp": 1}
    assert days["a"] == {"tn": 1, "fp": 1}
    assert days["b"] == {"fn": 1, "tp": 1}


def test_bad_model_probs_fail_closed():
    from collections import Counter, defaultdict
    class Encoder:
        def transform(self, records):
            return np.zeros((len(records), 1))
    class Estimator:
        def predict_proba(self, x):
            return np.array([[np.nan, np.nan]])
    with pytest.raises(ValueError, match="probabilities"):
        score._batch({"vectorizer": Encoder(), "estimator": Estimator()},
                     [score.adapt_v7_conn(fake_row())], [0], ["a"],
                     Counter(), defaultdict(Counter))


@pytest.mark.parametrize("value", [0, -1, 400001, 1.1])
def test_rows_limited_before_model_loading(value, monkeypatch, tmp_path):
    monkeypatch.setattr(score, "verify_bytes", lambda *args: (_ for _ in ()).throw(
        AssertionError("should never access data for invalid sample limit")
    ))
    with pytest.raises(ValueError):
        score.score_prefix(tmp_path, tmp_path, tmp_path, max_rows=value)
