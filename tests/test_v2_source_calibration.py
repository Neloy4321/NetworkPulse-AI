"""Source-only calibration policy, NO untouched-target-tuning or production claims."""
from datetime import datetime, timezone

import numpy as np
import pytest

from networkpulse.evaluation.v2_source_calibration import (
    GROUP_SEED, THRESHOLD_GRID, SOURCE_CAL_FPR_UPPER_MAX,
    is_calibration, source_split, select_dev_cutoff, recall_lower_bound,
    protocol,
)
from networkpulse.feature_contract_v2 import FlowV2


def event(i: int):
    return FlowV2(
        timestamp=datetime(2026, 10, 1, tzinfo=timezone.utc),
        source="zeek",
        src_ip=f"198.51.{i // 240}.{(i % 240) + 1}",
        dst_ip=f"203.0.{(i*7)//240 % 256}.{(i*7) % 240+1}",
        src_port=30000+i%32000, dst_port=443, proto="tcp",
        duration=1.2, orig_bytes=None if i%4 == 0 else 123,
        resp_bytes=222, orig_pkts=4, resp_pkts=7,
        label="anomaly" if i%2 else "benign",
    )


def test_source_only_registry_and_fixed_threshold_grid():
    p = protocol()
    assert GROUP_SEED == 1729
    assert SOURCE_CAL_FPR_UPPER_MAX == .025
    assert THRESHOLD_GRID[0] == .05
    assert THRESHOLD_GRID[-1] == .95
    assert p["never_use_hakai_torii_ton_cic_labels_for_cutoff"] is True
    assert "IoT-23v2" not in p.get("evaluation_targets", "")


def test_group_disjoint_split_reproducible_and_class_safe():
    original = [event(i) for i in range(6000)]
    train, cal = source_split(original)
    assert 3000 < len(train) < 5300
    assert 900 < len(cal) < 2000
    assert len({(str(e.src_ip), str(e.dst_ip), e.proto) for e in train} &
               {(str(e.src_ip), str(e.dst_ip), e.proto) for e in cal}) == 0
    assert all(not is_calibration(e) for e in train)
    assert all(is_calibration(e) for e in cal)
    assert (train, cal) == source_split(original)


def test_budgeted_threshold_selection_not_target_peeking():
    # Synthetic score fixtures are NOT measured network performance.
    labels = np.array([0]*800+[1]*400)
    scores = np.array([.02]*800+[.2]*400)
    selection = select_dev_cutoff(labels, scores)
    assert selection["status"] == "source_calibration_cutoff_selected"
    assert selection["cutoff"] == .05
    assert selection["source_cal_recall_lower_goal_met"] is True
    assert selection["source_cal_confusion"]["source_cal_fpr_upper95"] <= .025
    assert selection["untouched_holdout_scored"] is False


def test_calibration_refuses_to_weaken_fpr_to_chase_recall():
    labels = np.array([0]*800+[1]*400)
    scores = np.array([1.0]*800+[.99]*400)
    result = select_dev_cutoff(labels, scores)
    assert result["status"] == "blocked_source_calibration_fpr_budget"
    assert result["cutoff"] is None
    assert result["source_cal_recall_lower_goal_met"] is False


def test_small_class_support_or_invalid_scores_refused():
    with pytest.raises(ValueError, match="insufficient"):
        select_dev_cutoff([0,1],[.9,.8])
    labels = np.array([0]*800+[1]*400)
    values = np.array([.1]*1200)
    values[5] = np.nan
    with pytest.raises(ValueError, match="invalid"):
        select_dev_cutoff(labels, values)


def test_upper_lower_bounds_need_natural_support():
    assert recall_lower_bound(99, 100) > .90
    with pytest.raises(ValueError, match="invalid attack"):
        recall_lower_bound(2, 1)
    with pytest.raises(ValueError, match="unlabeled"):
        source_split([event(4).model_copy(update={"label": None})])
