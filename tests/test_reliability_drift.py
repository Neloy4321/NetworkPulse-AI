import pytest

from networkpulse.detector import train
from networkpulse.drift import drift_report, population_stability_index
from networkpulse.simulator import sample_flows


def test_reject_unrepresentative_drift_windows_and_invalid_thresholds():
    events = sample_flows(400, seed=44)
    d = train(events, seed=44)
    with pytest.raises(ValueError, match="30 events"):
        drift_report(d, events[:6])
    with pytest.raises(ValueError, match="PSI warning"):
        drift_report(d, events[:40], psi_warning=.6, psi_critical=.2)
    with pytest.raises(ValueError, match="population frequencies"):
        population_stability_index([0.3, -0.3], [.2, .8])


def test_labeled_drift_reports_confusion_but_cannot_retrain_implicitly():
    events = sample_flows(400, seed=45)
    d = train(events, seed=45)
    before = d.threshold
    labeled = drift_report(d, events[-90:])
    assert labeled["events"] == 90
    assert labeled["drift_status"] in {"normal", "warning", "critical"}
    assert labeled["labeled_window_diagnostics"]["benign_count"] > 0
    assert "fpr_wilson_upper_95_one_sided" in labeled["labeled_window_diagnostics"]
    assert before == d.threshold
    raw = [e.model_copy(update={"label": None}) for e in events[-40:]]
    assert "labeled_window_diagnostics" not in drift_report(d, raw)
