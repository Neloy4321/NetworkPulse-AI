"""Post-hoc domain diagnostics are descriptive, never a new acceptance gate."""
from types import SimpleNamespace

import pytest

from networkpulse.evaluation.domain_shift_diagnostics import alert_slices, feature_shift
from networkpulse.simulator import sample_flows


def test_feature_shift_does_not_emit_row_identifiers():
    original = sample_flows(120, seed=43)
    # One group is deliberately reused: this test checks aggregation contract.
    source = [x.model_copy(update={"label": "benign"}) for x in original[:70]]
    target = [x.model_copy(update={"label": "benign"}) for x in original[70:]]
    result = feature_shift(source, target)
    assert result["source_benign"] == 70
    assert result["target_benign"] == 50
    assert result["status"] == "posthoc_exploratory_only"
    assert "log_duration" in result["numeric_feature_summaries"]
    assert "src_ip" not in str(result) and "dst_ip" not in str(result)
    with pytest.raises(ValueError, match="30 authentic benign"):
        feature_shift(source, target[:3])


def test_slice_counts_and_small_state_suppressed():
    samples = sample_flows(180, seed=4)
    events = []
    predictions = []
    for i, event in enumerate(samples):
        events.append(event.model_copy(update={
            "label": "benign" if i < 90 else "anomaly",
            "proto": "tcp",
            "conn_state": "rare-state" if i < 2 else "sf",
        }))
        predictions.append(SimpleNamespace(
            anomalous=i % 5 == 0,
            anomaly_score=float(i) / 180,
        ))
    result = alert_slices(events, predictions)
    assert result["status"] == "posthoc_diagnostic_not_acceptance"
    tcp = result["by_protocol"][0]
    assert tcp["group"] == "tcp"
    assert tcp["benign"] == tcp["attack"] == 90
    assert tcp["confusion_matrix"] == {"tn": 72, "fp": 18, "fn": 72, "tp": 18}
    assert tcp["fpr"] == .2
    assert tcp["recall"] == .2
    assert [v["group"] for v in result["by_connection_state"]] == ["sf"]
    assert result["suppressed_small_groups"]["connection_state"] == 1


def test_refuse_incomplete_or_invalid_predictions():
    flows = [x.model_copy(update={"label": "benign"}) for x in sample_flows(40)]
    with pytest.raises(ValueError, match="every target"):
        alert_slices(flows, [])
    with pytest.raises(ValueError, match="Invalid native"):
        alert_slices(
            flows,
            [SimpleNamespace(anomalous="True", anomaly_score=.1)] * len(flows),
        )
