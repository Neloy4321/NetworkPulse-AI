"""Label-aware reliability reporting and benign calibration diagnostics.

No threshold is selected on the evaluation (held-out) labels. Confidence bounds
describe a finite evaluated sample, not guarantees under network distribution shift.
"""
from __future__ import annotations

import math
from collections import defaultdict
from statistics import NormalDist

import numpy as np


def wilson_upper_bound(errors: int, trials: int, *, confidence: float = 0.95) -> float:
    """One-sided Wilson upper confidence bound for a binomial error rate."""
    if not isinstance(errors, int) or not isinstance(trials, int):
        raise ValueError("counts must be integers")
    if not 0 <= errors <= trials or trials == 0:
        raise ValueError("need 0 <= errors <= trials and trials > 0")
    if not 0.5 < confidence < 1:
        raise ValueError("confidence must lie between .5 and 1")
    z = NormalDist().inv_cdf(confidence)
    p = errors / trials
    z2 = z * z
    value = (p + z2 / (2 * trials) +
             z * math.sqrt((p * (1 - p) + z2 / (4 * trials)) / trials)) / (
                 1 + z2 / trials
             )
    return round(float(min(1.0, value)), 6)


def confusion_profile(y_true, y_pred) -> dict:
    """Keep class counts and small-sample uncertainty explicit."""
    truth = np.asarray(y_true)
    pred = np.asarray(y_pred)
    if truth.ndim != 1 or pred.ndim != 1 or len(truth) != len(pred):
        raise ValueError("predictions and ground truth must have matching 1D lengths")
    if not len(truth) or not np.isin(truth, [0, 1]).all() or not np.isin(pred, [0, 1]).all():
        raise ValueError("binary predictions and truth required")
    tn = int(np.sum((truth == 0) & (pred == 0)))
    fp = int(np.sum((truth == 0) & (pred == 1)))
    fn = int(np.sum((truth == 1) & (pred == 0)))
    tp = int(np.sum((truth == 1) & (pred == 1)))
    benign = tn + fp
    attacks = fn + tp
    fpr = fp / benign if benign else None
    return {
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "benign_count": benign,
        "attack_count": attacks,
        "false_positive_rate": round(fpr, 6) if fpr is not None else None,
        "fpr_wilson_upper_95_one_sided": (
            wilson_upper_bound(fp, benign) if benign else None
        ),
        "attack_recall": round(tp / attacks, 6) if attacks else None,
        "alert_fraction": round((tp + fp) / len(truth), 6),
        "fpr_bound_assumption": (
            "One-sided binomial Wilson bound, conditional on evaluated sample; "
            "NOT robust to distribution shift, correlated flows or label errors."
        ),
    }


def calibration_diagnostics(scores, *, quantiles=(.95, .97, .99)) -> dict:
    """Descriptive benign-calibration-only thresholds; not a tuning search on test."""
    scores = np.asarray(scores, dtype=float)
    if scores.ndim != 1 or len(scores) < 20 or not np.isfinite(scores).all():
        raise ValueError("at least 20 finite benign calibration scores required")
    output = {}
    for quantile in quantiles:
        if not 0.5 < quantile < 1:
            raise ValueError("invalid calibration quantile")
        threshold = float(np.quantile(scores, quantile))
        above = int(np.sum(scores >= threshold))
        # Calibrated in-sample rates aren't real future FPR estimates.
        output[str(quantile)] = {
            "threshold": round(threshold, 8),
            "in_sample_benign_alerts": above,
            "in_sample_benign_alert_fraction": round(above / len(scores), 6),
        }
    return {
        "count": len(scores),
        "quantiles": output,
        "note": "Diagnostic thresholds are fit only to training-period benign calibration; "
                "their observed rates are in-sample, NOT prospective FPR guarantees.",
    }


def reliability_slices(events, detections, *, min_benign: int = 20) -> dict:
    """Leakage-free auditing by protocol, event source and port class.

    Inputs must have independently verified labels. No flow identities are
    exported. Tiny slices retain counts but withhold unstable error estimates.
    """
    if not 1 <= min_benign <= 10000 or len(events) != len(detections):
        raise ValueError("invalid slice minimum or sample lengths")
    if not events or any(e.label not in {"benign", "anomaly"} for e in events):
        raise ValueError("complete independent binary labels required")
    groups = defaultdict(list)
    for event, detection in zip(events, detections):
        groups[("protocol", event.proto)].append((event, detection))
        groups[("sensor", event.source)].append((event, detection))
        groups[("port_class", "well_known" if event.dst_port < 1024 else "registered_dynamic")].append(
            (event, detection)
        )
    output = {}
    for (dimension, group), items in sorted(groups.items()):
        profile = confusion_profile(
            [int(e.label == "anomaly") for e, _ in items],
            [int(d.anomalous) for _, d in items],
        )
        if profile["benign_count"] < min_benign:
            profile["false_positive_rate"] = None
            profile["fpr_wilson_upper_95_one_sided"] = None
            profile["withheld_reason"] = "too few labeled benign records"
        output.setdefault(dimension, {})[group] = profile
    return {"min_benign_for_slice_rate": min_benign, "slices": output,
            "sampling_warning": "Slices describe this selected labeled holdout only; "
                                "no cross-site independence is implied."}
