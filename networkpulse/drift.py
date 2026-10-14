"""Explicit model baseline monitoring: PSI, expected anomaly volume, provenance.

PSI flags distribution change; it does not prove the model has degraded, nor
infer attack labels from unlabeled production logs.
"""

from __future__ import annotations

import math

import numpy as np

from networkpulse.features import event_features
from networkpulse.schemas import FlowEvent
from networkpulse.reliability import confusion_profile


def make_reference(vectors: np.ndarray) -> dict:
    if vectors.ndim != 2 or vectors.shape[0] < 20:
        raise ValueError("at least 20 training events required for a drift baseline")
    return {"count": int(len(vectors)), "features": [
        {"edges": [float(x) for x in np.unique(np.quantile(vectors[:, idx],np.linspace(0,1,11))[1:-1])],
         "distribution": _frequencies(vectors[:,idx],np.unique(np.quantile(vectors[:, idx],np.linspace(0,1,11))[1:-1])).tolist()}
        for idx in range(vectors.shape[1])
    ]}


def _frequencies(values: np.ndarray, edges: np.ndarray) -> np.ndarray:
    counts=np.bincount(np.searchsorted(edges,values,side="right"),minlength=len(edges)+1)
    return counts / max(1,len(values))


def population_stability_index(expected: list[float],observed: list[float]) -> float:
    if len(expected) != len(observed) or not expected:
        raise ValueError("population bins differ")
    if any(not math.isfinite(float(v)) or float(v) < 0
           for v in expected + observed):
        raise ValueError("invalid population frequencies")
    eps=1e-6
    return float(sum((o-e)*math.log((o+eps)/(e+eps)) for e,o in zip(expected,observed)))


def drift_report(detector, events: list[FlowEvent], *, psi_warning: float=.2,
                 psi_critical: float=.4, max_alert_fraction: float=.15) -> dict:
    baseline=detector.metadata.get("drift_baseline")
    if not baseline:
        raise ValueError("model has no drift baseline; retrain from trusted data")
    if not 0 < psi_warning < psi_critical:
        raise ValueError("drift PSI warning must be below critical and positive")
    if not 0 < max_alert_fraction <= 1:
        raise ValueError("drift alert budget must lie in (0, 1]")
    if len(events) < 30:
        raise ValueError("drift requires at least 30 events per reporting window")
    vectors=detector.vectorizer.transform([event_features(x) for x in events])
    if len(baseline["features"]) != vectors.shape[1]:
        raise ValueError("model baseline dimensions mismatch")
    if not np.isfinite(vectors).all():
        raise ValueError("nonfinite observation feature vector")
    results=[]
    for name, feature_ref, column in zip(detector.vectorizer.feature_names_,baseline["features"],vectors.T):
        distribution=_frequencies(column,np.array(feature_ref["edges"]))
        psi=population_stability_index(feature_ref["distribution"],distribution.tolist())
        results.append({"feature":name,"psi":round(psi,5),"status":"critical" if psi>=psi_critical else "warning" if psi>=psi_warning else "normal"})
    scored=detector.score(events)
    alarms=sum(x.anomalous for x in scored)
    worst_psi = max(x["psi"] for x in results)
    report = {
        "events": len(events), "alerts": alarms,
        "alert_fraction": round(alarms / len(events), 5),
        "alert_budget_exceeded": alarms / len(events) > max_alert_fraction,
        "features": results, "worst_psi": worst_psi,
        "drift_status": ("critical" if worst_psi >= psi_critical else
                         "warning" if worst_psi >= psi_warning else "normal"),
        "confidence_warning": (
            "PSI windows may contain correlated sessions and are not independent; "
            "monitor consecutive windows and confirmed labels before model changes."
        ),
        "limitations": "Distribution monitoring is unsupervised; drift alone does not "
                       "establish prediction error or malicious intent.",
    }
    if all(e.label in {"benign", "anomaly"} for e in events):
        report["labeled_window_diagnostics"] = confusion_profile(
            [int(e.label == "anomaly") for e in events],
            [int(x.anomalous) for x in scored],
        )
        report["labeled_window_note"] = (
            "Optional retrospective labeled diagnostics; labels not used to compute PSI "
            "or set thresholds. Not deployment accuracy without verified provenance."
        )
    return report
