"""Contract tests for predeclared calibration policies."""
import pytest

from networkpulse.evaluation.calibration_study import (
    POLICIES, _event_identity_unique, compare_calibration_policies,
)
from networkpulse.simulator import sample_flows


def test_calibration_quantiles_fixed_and_unique_flow_identity():
    assert POLICIES == (0.97, 0.99, 0.995)
    flows = sample_flows(110, seed=42)
    assert len(_event_identity_unique(flows[:20] + flows[:20])) == 20
    deny = {x.key() for x in flows[:5]}
    assert len(_event_identity_unique(flows[:15], deny)) == 10


def test_reject_small_reliability_trial(tmp_path):
    with pytest.raises(ValueError, match="sample caps too small"):
        compare_calibration_policies(tmp_path/"none.zip", train_cap=99)
