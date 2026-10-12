"""Temporal separation, benign-only model fit and held-out evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import average_precision_score, precision_recall_fscore_support, roc_auc_score

from networkpulse.features import FEATURE_VERSION, event_features, explain
from networkpulse.schemas import FlowEvent


@dataclass
class Detection:
    anomaly_score: float
    threshold: float
    anomalous: bool
    risk: int
    reasons: list[str]


@dataclass
class Detector:
    vectorizer: DictVectorizer
    estimator: IsolationForest
    threshold: float
    scale: float
    metadata: dict

    def score(self, events: list[FlowEvent]) -> list[Detection]:
        if not events:
            return []
        vectors = self.vectorizer.transform([event_features(e) for e in events])
        scores = -self.estimator.decision_function(vectors)
        return [
            Detection(
                anomaly_score=round(float(score), 6),
                threshold=round(self.threshold, 6),
                anomalous=bool(score >= self.threshold),
                risk=int(round(np.clip(50 + (score - self.threshold) / self.scale * 24, 0, 100))),
                reasons=explain(event),
            )
            for score, event in zip(scores, events)
        ]

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path, compress=3)

    @classmethod
    def load(cls, path: Path) -> Detector:
        # joblib loads pickle. Only load artifacts you created/trust; never user uploads.
        obj = joblib.load(path)
        if not isinstance(obj, cls) or obj.metadata.get("feature_version") != FEATURE_VERSION:
            raise ValueError("incompatible or untrusted model artifact")
        return obj


def train(
    data: list[FlowEvent],
    quantile: float = 0.97,
    seed: int = 42,
    source: str = "synthetic_demo",
) -> Detector:
    """Chronological train 60%, calibration 15%, holdout 25%.

    The unsupervised detector is fit on benign earlier events. Threshold chosen
    from separate benign calibration window; later labels used *only* for metrics.
    """
    if not 0.85 <= quantile <= 0.999:
        raise ValueError("quantile must be between 0.85 and 0.999")
    ordered = sorted(data, key=lambda e: e.timestamp)
    n = len(ordered)
    if n < 100:
        raise ValueError("training requires at least 100 chronological events")
    a, b = int(n * .60), int(n * .75)
    train_set = [e for e in ordered[:a] if e.label != "anomaly"]
    cal_set = [e for e in ordered[a:b] if e.label != "anomaly"]
    holdout = ordered[b:]
    if len(train_set) < 50 or len(cal_set) < 20:
        raise ValueError("insufficient benign events for training/calibration")
    encoder = DictVectorizer(sparse=False)
    features = encoder.fit_transform([event_features(e) for e in train_set])
    estimator = IsolationForest(n_estimators=180, max_samples="auto", random_state=seed,
                                contamination="auto", n_jobs=1)
    estimator.fit(features)
    cal_features = encoder.transform([event_features(e) for e in cal_set])
    scores = -estimator.decision_function(cal_features)
    threshold = float(np.quantile(scores, quantile))
    scale = float(max(np.quantile(scores, .95) - np.quantile(scores, .50), 0.025))
    detector = Detector(
        vectorizer=encoder,
        estimator=estimator,
        threshold=threshold,
        scale=scale,
        metadata={
            "version": "0.1.0", "feature_version": FEATURE_VERSION,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "source": source, "seed": seed, "quantile": quantile,
            "train_count": len(train_set), "cal_count": len(cal_set),
            "holdout_count": len(holdout), "holdout_first": holdout[0].timestamp.isoformat(),
            "feature_count": features.shape[1],
        },
    )
    if all(e.label is not None for e in holdout):
        y_true = np.asarray([int(e.label == "anomaly") for e in holdout])
        measured = detector.score(holdout)
        y_pred = np.asarray([int(e.anomalous) for e in measured])
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_true, y_pred, average="binary", zero_division=0
        )
        metrics = {
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1": round(float(f1), 4),
            "alerts": int(y_pred.sum()),
            "holdout_anomalies": int(y_true.sum()),
        }
        if len(np.unique(y_true)) == 2:
            metrics["roc_auc"] = round(float(roc_auc_score(y_true, [x.anomaly_score for x in measured])), 4)
            metrics["average_precision"] = round(float(average_precision_score(y_true, [x.anomaly_score for x in measured])), 4)
        detector.metadata["metrics"] = metrics
    else:
        detector.metadata["metrics"] = None
    return detector
