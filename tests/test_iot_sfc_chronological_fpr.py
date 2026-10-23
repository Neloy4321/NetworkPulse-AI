"""Unit tests for prospective date-fenced IoT-SFC v7 FPR repair.

Tests are synthetic: no target CSV, private IP data or model binaries.
"""
from __future__ import annotations

from datetime import date

import numpy as np
import pytest

from networkpulse.evaluation import iot_sfc_chronological_fpr as chrono
from networkpulse.evaluation.iot_sfc_frozen_score import adapt_v7_conn


def _flow(i: int):
    row = {
        "ts": str(1743681600 + i),
        "log_type": "conn",
        "uid": f"synthetic-{i}",
        "orig_h": "192.0.2.10",
        "orig_p": "10123",
        "resp_h": "198.51.100.20",
        "resp_p": "443",
        "proto": "tcp",
        "duration": "0.5",
        "orig_bytes": "150",
        "resp_bytes": "500",
        "orig_pkts": "2",
        "resp_pkts": "4",
        "conn_state": "SF",
    }
    return adapt_v7_conn(row)


def test_future_days_not_used_as_train_or_calibration():
    assert chrono.TRAIN_MAX == date(2025, 4, 8)
    assert chrono.CAL_DATE == date(2025, 4, 10)
    assert chrono.TEST_MIN == date(2025, 4, 12)
    assert chrono.TRAIN_MAX < chrono.CAL_DATE < chrono.TEST_MIN
    assert chrono.EVAL_END == 450_000
    assert chrono.MIN_DAYS == 3
    assert chrono.RESEARCH_FPR_UPPER == .05
    assert chrono.RESEARCH_RECALL_LOWER == .80
    assert chrono.BASELINE_CUTOFF == .20


def test_dev_does_not_select_without_sufficient_positives():
    xs = [_flow(i) for i in range(350)]
    ys = np.array([0] * 300 + [1] * 50)
    result = None
    with pytest.raises(ValueError, match="FIT/DEV class support"):
        result = chrono.choose_on_exposed_apr10(
            xs, ys, xs, ys,
        )
    assert result is None


def test_dev_support_selection_is_pinned_and_does_not_need_future_data(monkeypatch):
    class FakeEstimator:
        def fit(self, x, labels):
            assert x.shape[0] == len(labels)
            self.prior = float(np.mean(labels))
            return self

        def predict_proba(self, x):
            # Deterministic synthetic classifier; no external labels/bytes.
            positive = np.asarray([0.98 if v[-1] else 0.02 for v in x], dtype=float)
            return np.column_stack((1 - positive, positive))

    class FakeEncoder:
        def fit_transform(self, values):
            return np.asarray(
                [[float(i % 2), float(i % 2)] for i in range(len(values))],
            )
        def transform(self, values):
            return np.asarray(
                [[float(i % 2), float(i % 2)] for i in range(len(values))],
            )

    monkeypatch.setattr(chrono, "DictVectorizer", lambda **_: FakeEncoder())
    monkeypatch.setattr(chrono, "make_model", lambda params: FakeEstimator())
    train = [_flow(i) for i in range(600)]
    dev = [_flow(i + 1000) for i in range(600)]
    y_train = np.array([i % 2 for i in range(600)])
    y_dev = np.array([i % 2 for i in range(600)])
    decision, model, encoder = chrono.choose_on_exposed_apr10(
        train, y_train, dev, y_dev,
    )
    assert decision["selection"] is not None
    assert decision["selection"]["dev_fpr_upper95"] <= .03
    assert decision["source_fit"] == {0: 300, 1: 300}
    assert decision["source_cal"] == {0: 300, 1: 300}
    assert model is not None and encoder is not None


def test_missing_test_class_support_never_promoted():
    assert chrono.MIN_TEST_BENIGN >= 200
    assert chrono.MIN_TEST_ATTACK >= 100
    assert chrono.TEST_MAX > chrono.TEST_MIN
    assert chrono.TARGET_SCORED_ROWS >= 100_000


def test_partial_prefix_is_never_misreported_as_site_independent():
    assert chrono.TEST_MIN > date(2025, 4, 10)
    assert chrono.MODEL_OPTIONS
    assert set(chrono.MODEL_OPTIONS) == {
        "rf_regularized", "rf_deeper", "extra_trees"
    }
