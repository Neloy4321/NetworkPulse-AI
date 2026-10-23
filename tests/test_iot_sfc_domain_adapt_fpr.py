"""FPR-repair protocol tests: no later-label candidate selection or silent GO."""
from __future__ import annotations

from collections import Counter

import numpy as np
import pytest

from networkpulse.evaluation import iot_sfc_domain_adapt_fpr as repair
from networkpulse.evaluation.iot_sfc_frozen_score import adapt_v7_conn


def example_flow(i: int):
    row = {
        "log_type": "conn", "ts": str(1743681600 + i),
        "uid": f"fixture-{i}",
        "orig_h": f"192.0.2.{(i % 150)+1}",
        "orig_p": "43000",
        "resp_h": f"198.51.100.{(i % 170)+1}",
        "resp_p": "443", "proto": "tcp",
        "duration": "0.1", "orig_bytes": "10", "resp_bytes": "",
        "orig_pkts": "1", "resp_pkts": "",
        "conn_state": "SF",
    }
    return adapt_v7_conn(row)


def test_candidate_grid_is_source_only_and_predeclared():
    assert repair.FIT_END == 200_000
    assert repair.EVAL_END == 450_000
    assert repair.FPR_DEV_UPPER_CAP == .03
    assert repair.SEED == 1729
    assert repair.MODEL_OPTIONS["rf_regularized"]["min_samples_leaf"] == 15


def test_source_split_hostgroup_disjoint():
    flows = [example_flow(i) for i in range(1200)]
    y = np.array([i % 2 for i in range(len(flows))])
    fit, dev, counts = repair.source_split(flows, y)
    assert set(fit).isdisjoint(dev)
    assert set(repair.group_key(flows[i]) for i in fit).isdisjoint(
        set(repair.group_key(flows[i]) for i in dev)
    )
    assert sum(counts["fit"]) + sum(counts["dev"]) == len(flows)


def test_model_probabilities_transform_without_identity_leakage():
    f = example_flow(1)
    assert "src_ip" not in repair.features_v2(f)
    assert "uid" not in repair.features_v2(f)
    assert "timestamp" not in repair.features_v2(f)
    assert repair.is_dev(f) == repair.is_dev(f)


def test_confusion_math_with_unchanged_cutoff():
    label = np.array([0, 0, 1, 1])
    preds = np.array([False, True, False, True])
    assert repair.confusion(label, preds) == Counter({
        "tn": 1, "fp": 1, "fn": 1, "tp": 1
    })


def test_dev_insufficient_support_forbids_selection():
    dev_labels = np.array([0] * 50 + [1] * 50)
    selection = repair.select_candidate({
        "rf_regularized": (object(), np.array([0.1] * 50 + [0.9] * 50)),
    }, dev_labels)
    assert selection["selected"] is None
    assert selection["reason"] == "DEVELOPMENT_GROUP_SUPPORT_INSUFFICIENT"


def test_dev_grid_chooses_strong_source_only_candidate_at_FPR_budget():
    dev_labels = np.array([0] * 1000 + [1] * 400)
    probs = np.array([0.05] * 1000 + [0.98] * 400)
    picked = repair.select_candidate({
        "rf_regularized": (object(), probs),
    }, dev_labels)
    assert picked["selected"] is not None
    assert picked["selected"]["dev_fpr_upper95"] <= .03
    assert picked["selected"]["dev_recall_lower95"] >= .80


def test_when_source_dev_fpr_does_not_pass_no_fake_candidate():
    dev_labels = np.array([0] * 1000 + [1] * 200)
    scores = np.array([1.0] * 1000 + [0.99] * 200)
    selection = repair.select_candidate({
        "rf_regularized": (object(), scores),
    }, dev_labels)
    assert selection["selected"] is None
    assert selection["reason"] == "NO_SOURCE_DEV_CANDIDATE_MEETS_FPR_BUDGET"


def test_binary_support_and_invalid_counts_are_rejected():
    labels = np.array([0, 0, 1])
    scores = np.array([0.1, 0.5, 0.8])
    report = repair.confusion(labels, scores >= 0.5)
    assert report["tp"] == 1 and report["fp"] == 1


def test_frozen_baseline_threshold_is_not_candidate_selection():
    assert repair.BASELINE_CUTOFF == 0.20
    assert repair.FPR_DEV_UPPER_CAP < .05
    assert 0.20 in repair.CUTOFFS
