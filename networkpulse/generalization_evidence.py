"""Leakage-aware frozen-model external-domain IDS acceptance evaluation.

No training, resampling, threshold selection, or mutation of the input model.
Reports contain aggregated counts only. The independent-capture attestation is
operator-supplied and does not independently establish dataset provenance.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from sklearn.metrics import average_precision_score

_HEX = frozenset("0123456789abcdef")


def valid_sha(value: str) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in _HEX for c in value)


def normalized_flow_fingerprint(event) -> str:
    """Hash the same flow independently of adapter source, UID and label.

    Retaining original event time, addresses, ports and counters reduces false
    overlap reports for similar-but-distinct traffic. This cannot detect
    transformed captures whose timestamps or flow counters were changed.
    """
    content = event.model_dump(mode="json", exclude={"source", "uid", "label"})
    data = json.dumps(content, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class TrainingLedger:
    canonical_ids: frozenset[str]
    normalized_fingerprints: frozenset[str]


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


@dataclass(frozen=True)
class ExternalHoldoutSpec:
    """Pre-registered acceptance contract. Never tuned using the holdout."""

    train_domain: str
    holdout_domain: str
    training_sha256: str
    holdout_sha256: str
    model_sha256: str
    acquisition_statement: str
    label_provenance: str
    independent_capture_attested: bool
    max_false_positive_rate: float
    min_true_positive_rate: float
    min_benign: int = 100
    min_attack: int = 50
    min_capture_days: int = 3
    max_rows: int = 250_000

    def validate(self) -> None:
        if not self.train_domain.strip() or not self.holdout_domain.strip():
            raise ValueError("Training and holdout domains must be named")
        if self.train_domain.strip().casefold() == self.holdout_domain.strip().casefold():
            raise ValueError("External holdout must be a distinct named domain")
        for name in ("training_sha256", "holdout_sha256", "model_sha256"):
            if not valid_sha(getattr(self, name)):
                raise ValueError(f"{name} must be exact lowercase SHA256")
        if self.training_sha256 == self.holdout_sha256:
            raise ValueError("Training and holdout source hashes are identical")
        if not self.independent_capture_attested:
            raise ValueError("Independent-capture operator attestation is required")
        if len(self.acquisition_statement.strip()) < 15 or len(self.label_provenance.strip()) < 15:
            raise ValueError("Source acquisition and independent label provenance are required")
        if not (0 < self.max_false_positive_rate < 1):
            raise ValueError("False-positive acceptance bound must be strictly between 0 and 1")
        if not (0 < self.min_true_positive_rate < 1):
            raise ValueError("Recall acceptance bound must be strictly between 0 and 1")
        if not (100 <= self.min_benign <= self.max_rows <= 250_000):
            raise ValueError("Invalid benign/row limits")
        if not (25 <= self.min_attack <= self.max_rows):
            raise ValueError("Invalid attack count requirement")
        if not (2 <= self.min_capture_days <= 60):
            raise ValueError("Independent day coverage must be 2..60")

    @classmethod
    def from_json(cls, path: Path) -> ExternalHoldoutSpec:
        obj = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(obj, dict) or set(obj) != set(cls.__dataclass_fields__):
            # Permit omission of fields with dataclass defaults, but refuse unknown knobs.
            if not isinstance(obj, dict) or set(obj) - set(cls.__dataclass_fields__):
                raise ValueError("Holdout specification contains unknown fields")
        value = cls(**obj)
        value.validate()
        return value


def wilson_interval(successes: int, trials: int, z: float = 1.95996398454) -> tuple[float, float]:
    """Wilson binomial CI, diagnostic only when flows are correlated."""
    if trials <= 0 or successes < 0 or successes > trials:
        raise ValueError("Invalid Bernoulli counts")
    p = successes / trials
    d = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / d
    half = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / d
    return max(0., center - half), min(1., center + half)


def _aggregate(records: Iterable[tuple[str, str, bool, bool, float]], *, limit: int):
    """Consume (key, day, label, prediction, score) observations."""
    matrix = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    per_day = defaultdict(lambda: {"tp": 0, "tn": 0, "fp": 0, "fn": 0})
    keys = set()
    labels, scores = [], []
    for item in records:
        if len(item) != 5:
            raise ValueError("Internal observation contract mismatch")
        key, day, actual, predicted, score = item
        if len(keys) >= limit:
            raise ValueError("Holdout exceeds pre-registered row limit")
        if key in keys:
            raise ValueError("Duplicate canonical flow key in independent holdout")
        if not (isinstance(actual, bool) and isinstance(predicted, bool)
                and isinstance(score, (int, float)) and math.isfinite(float(score))):
            raise ValueError("Malformed prediction or label")
        keys.add(key)
        slot = ("tp" if actual else "fp") if predicted else ("fn" if actual else "tn")
        matrix[slot] += 1
        per_day[day][slot] += 1
        labels.append(int(actual))
        scores.append(float(score))
    return matrix, per_day, labels, scores, keys


def evaluate_frozen_holdout(
    *, spec: ExternalHoldoutSpec, model_path: Path, corpus_path: Path,
    records_factory: Callable[[], Iterable], detector_loader: Callable[[Path], object],
    training_keys: TrainingLedger | None = None,
) -> dict:
    """Evaluate one explicitly pinned independent corpus and frozen model.

    ``records_factory`` must yield FlowEvent objects with .label, .source,
    .timestamp, .key(). Canonical JSONL is provided by the CLI entry point.
    Production model's .score(batch) must emit Detection objects. Thresholds
    are NOT reselected and metric counts are NEVER changed after evaluation.
    """
    spec.validate()
    if digest_file(model_path) != spec.model_sha256:
        raise ValueError("Frozen model SHA256 pin mismatch; refusing unpickle")
    if digest_file(corpus_path) != spec.holdout_sha256:
        raise ValueError("Holdout bytes changed from approved SHA256")
    if training_keys is None:
        # The training-ID ledger is essential to prove record non-overlap.
        raise ValueError("Verified source-training event-ID ledger is required")
    if not training_keys.canonical_ids or not training_keys.normalized_fingerprints:
        raise ValueError("Training event-ID ledger cannot be empty")
    detector = detector_loader(model_path)
    # Score all records without writing flow metadata or retraining.
    def observed():
        chunk = []
        observed_fingerprints = set()
        observed_ids = set()
        for event in records_factory():
            if event.source == "simulator":
                raise ValueError("Synthetic simulator records cannot validate field generalization")
            if event.label not in ("benign", "anomaly"):
                raise ValueError("Every holdout event requires independently labeled ground truth")
            key = event.key()
            if key in observed_ids:
                raise ValueError("Duplicate canonical flow key in independent holdout")
            observed_ids.add(key)
            if key in training_keys.canonical_ids:
                raise ValueError("Training/holdout canonical-ID overlap detected")
            fingerprint = normalized_flow_fingerprint(event)
            if fingerprint in training_keys.normalized_fingerprints:
                raise ValueError("Training/holdout normalized-flow overlap detected")
            if fingerprint in observed_fingerprints:
                raise ValueError("Duplicate normalized flow in independent holdout")
            observed_fingerprints.add(fingerprint)
            if len(observed_fingerprints) > spec.max_rows:
                raise ValueError("Holdout exceeds pre-registered row limit")
            chunk.append(event)
            if len(chunk) >= 128:
                yield from batch_observations(chunk)
                chunk = []
        if chunk:
            yield from batch_observations(chunk)

    def batch_observations(batch):
        detection = detector.score(batch)
        if len(detection) != len(batch):
            raise ValueError("Detector returned the wrong number of scores")
        for event, pred in zip(batch, detection):
            if type(pred.anomalous) is not bool:
                raise ValueError("Invalid detector anomaly outcome")
            yield (event.key(), event.timestamp.date().isoformat(),
                   event.label == "anomaly", pred.anomalous, pred.anomaly_score)

    counts, days, actual, scores, keys = _aggregate(observed(), limit=spec.max_rows)
    # Rehash corpus after reading, detecting mid-evaluation replacement.
    if digest_file(corpus_path) != spec.holdout_sha256:
        raise ValueError("Holdout source changed during evaluation")
    if not keys:
        raise ValueError("No labeled real holdout events")
    benign = counts["tn"] + counts["fp"]
    attack = counts["tp"] + counts["fn"]
    fpr = counts["fp"] / benign if benign else None
    tpr = counts["tp"] / attack if attack else None
    ci_fpr = wilson_interval(counts["fp"], benign) if benign else None
    ci_tpr = wilson_interval(counts["tp"], attack) if attack else None
    daily = []
    for day in sorted(days):
        row = days[day]
        n_benign = row["tn"] + row["fp"]
        n_attack = row["tp"] + row["fn"]
        daily.append({"day": day, "benign": n_benign, "attack": n_attack,
                      "false_positive_rate": row["fp"] / n_benign if n_benign else None,
                      "recall": row["tp"] / n_attack if n_attack else None})
    # Wilson CI assumes independent Bernoulli observations. Network flow
    # correlation means it is OPTIMISTIC; require day-level support as well.
    sufficient = benign >= spec.min_benign and attack >= spec.min_attack
    coverage = len([x for x in daily if x["benign"] > 0]) >= spec.min_capture_days
    status = "passed" if (sufficient and coverage and
             ci_fpr is not None and ci_fpr[1] <= spec.max_false_positive_rate and
             ci_tpr is not None and ci_tpr[0] >= spec.min_true_positive_rate and
             all(x["false_positive_rate"] <= spec.max_false_positive_rate
                 for x in daily if x["false_positive_rate"] is not None)) else "failed"
    precision = counts["tp"] / (counts["tp"] + counts["fp"]) if counts["tp"] + counts["fp"] else 0.0
    recall = tpr or 0.0
    return {
        "schema_version": 1, "status": status,
        "scope": "frozen_cross_domain_labeled_holdout_not_field_certification",
        "train_domain": spec.train_domain, "holdout_domain": spec.holdout_domain,
        "training_sha256": spec.training_sha256,
        "holdout_sha256": spec.holdout_sha256,
        "model_sha256": spec.model_sha256,
        "training_ids_overlap": 0, "normalized_flow_overlap": 0,
        "unique_holdout_events": len(keys),
        "class_counts": {"benign": benign, "anomaly": attack},
        "confusion_matrix": counts,
        "precision": round(precision, 6), "recall": round(recall, 6),
        "f1": round(2 * precision * recall / (precision + recall), 6)
              if precision + recall else 0.0,
        "false_positive_rate": round(fpr, 6) if fpr is not None else None,
        "fpr_wilson_95": [round(x, 6) for x in ci_fpr] if ci_fpr else None,
        "recall_wilson_95": [round(x, 6) for x in ci_tpr] if ci_tpr else None,
        "average_precision": round(float(average_precision_score(actual, scores)), 6)
                              if benign and attack else None,
        "capture_days_with_benign": sum(x["benign"] > 0 for x in daily),
        "per_day": daily,
        "acceptance": {
            "max_fpr": spec.max_false_positive_rate,
            "min_recall": spec.min_true_positive_rate,
            "min_benign": spec.min_benign, "min_attack": spec.min_attack,
            "min_days": spec.min_capture_days,
            "min_days_met": coverage, "sample_floor_met": sufficient,
            "ci_independence_warning": "Flow-level Wilson intervals may understate correlation risk",
        },
        "provenance": {
            "source_acquisition_statement_sha256": hashlib.sha256(
                spec.acquisition_statement.encode("utf-8")
            ).hexdigest(),
            "label_provenance_statement_sha256": hashlib.sha256(
                spec.label_provenance.encode("utf-8")
            ).hexdigest(),
            "independence_operator_attested_not_cryptographically_proved": True,
        },
        "limitations": [
            "Source/label provenance are operator attestations, not independently verified",
            "Observational holdout does not measure sensor-to-alert or live deployment behavior",
            "False-positive intervals assume independent flows; correlated traffic may widen uncertainty",
            "No retraining, per-holdout threshold optimization or label-informed sampling performed",
        ],
    }


def load_training_keys(path: Path, expected_sha256: str,
                       *, max_keys: int = 500_000) -> TrainingLedger:
    """Read restricted canonical-ID and cross-adapter fingerprint TSV ledger."""
    if not valid_sha(expected_sha256) or digest_file(path) != expected_sha256:
        raise ValueError("Training event-ID ledger SHA256 mismatch")
    keys, fingerprints = set(), set()
    with path.open("rt", encoding="utf-8") as handle:
        for raw in handle:
            parts = raw.rstrip("\n").split("\t")
            if len(parts) != 2:
                raise ValueError("Invalid 2-column training ledger record")
            key, fingerprint = parts
            if (len(key) != 32 or any(c not in _HEX for c in key)
                    or not valid_sha(fingerprint)):
                raise ValueError("Invalid canonical ID or normalized fingerprint")
            if key in keys:
                raise ValueError("Duplicate entry in training event-ID ledger")
            if len(keys) >= max_keys:
                raise ValueError("Training ID ledger exceeds bounded cap")
            keys.add(key)
            fingerprints.add(fingerprint)
    if digest_file(path) != expected_sha256:
        raise ValueError("Training event-ID ledger changed during evaluation")
    return TrainingLedger(frozenset(keys), frozenset(fingerprints))


def write_evidence_once(path: Path, report: dict) -> None:
    """No overwrite; atomically publish mode 0600 JSON with fsync."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, pending = tempfile.mkstemp(prefix=".generalization-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            os.fchmod(f.fileno(), 0o600)
            json.dump(report, f, sort_keys=True, indent=2, allow_nan=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.link(pending, path)
        parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if os.path.exists(pending):
            os.unlink(pending)


def verify_training_source_ledger(source: Path, source_sha256: str,
                                  ledger_sha256: str, *, max_rows: int = 500_000) -> int:
    """Recompute the exact ledger from an independently pinned original source."""
    from networkpulse.adapters import iter_jsonl

    if not valid_sha(source_sha256) or digest_file(source) != source_sha256:
        raise ValueError("Original training corpus SHA256 mismatch")
    if not valid_sha(ledger_sha256):
        raise ValueError("Training ledger SHA256 is invalid")
    records, seen = [], set()
    for event in iter_jsonl(source, "canonical"):
        key = event.key()
        if key in seen:
            raise ValueError("Original training corpus contains duplicate canonical keys")
        if len(records) >= max_rows:
            raise ValueError("Original training source exceeds bounded ledger cap")
        seen.add(key)
        records.append((key, normalized_flow_fingerprint(event)))
    if not records or digest_file(source) != source_sha256:
        raise ValueError("Original training source is empty or changed during verification")
    digest = hashlib.sha256()
    for key, fingerprint in sorted(records):
        digest.update((key + "\t" + fingerprint + "\n").encode("utf-8"))
    if digest.hexdigest() != ledger_sha256:
        raise ValueError("Original training corpus and ID ledger do not match")
    return len(records)
