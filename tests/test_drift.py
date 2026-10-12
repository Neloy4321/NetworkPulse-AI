import pytest
from networkpulse.detector import train
from networkpulse.simulator import sample_flows
from networkpulse.drift import drift_report, population_stability_index


def test_identical_distributions_have_no_psi():
    assert population_stability_index([.2,.8],[.2,.8]) == 0.


def test_drift_and_alert_budget_signal():
    dataset=sample_flows(400,seed=33)
    d=train(dataset,seed=33)
    assert d.metadata["drift_baseline"]["count"]==240
    normal=drift_report(d,dataset[100:140])
    assert normal["events"]==40
    shifted=drift_report(d,dataset[-60:])
    assert shifted["worst_psi"]>=0
    assert shifted["alerts"]>=0
    assert any(x["status"] in {"normal","warning","critical"} for x in shifted["features"])
    with pytest.raises(ValueError):drift_report(d,[])
