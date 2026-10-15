"""Frozen cross-dataset ML generalization acceptance regression tests.

These are synthetic fixtures for code correctness, not an external IDS claim.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from networkpulse.generalization_evidence import (
    ExternalHoldoutSpec, TrainingLedger, evaluate_frozen_holdout, load_training_keys,
    normalized_flow_fingerprint, wilson_interval, write_evidence_once,
)


@dataclass
class Event:
    identifier: str
    timestamp: datetime
    label: str
    source: str = "canonical"
    flow_port: int | None = None

    def key(self):
        return self.identifier

    def model_dump(self, mode="json", exclude=None):
        payload = {"timestamp": self.timestamp.isoformat(), "src_ip": "10.0.1.2",
                   "dst_ip": "10.0.1.3", "src_port": self.flow_port or (1024 + int(self.identifier, 16) % 50000), "dst_port": 443,
                   "proto": "tcp", "orig_bytes": 80, "resp_bytes": 400,
                   "source": self.source, "uid": self.identifier, "label": self.label}
        return {k: v for k, v in payload.items() if k not in (exclude or ())}


class PerfectFrozenDetector:
    def score(self, batch):
        return [SimpleNamespace(
            anomalous=e.label == "anomaly",
            anomaly_score=.8 if e.label == "anomaly" else .1,
        ) for e in batch]


def dataset():
    events = []
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    for i in range(360):
        events.append(Event(
            identifier=f"{i+1:032x}",
            timestamp=start + timedelta(days=i // 120),
            label="benign" if i % 2 else "anomaly",
        ))
    return events


def case(tmp_path, events=None):
    model = tmp_path / "pinned-model.joblib"
    model.write_bytes(b"approved-test-fixture-model")
    corpus = tmp_path / "external-holdout.jsonl"
    corpus.write_text("\n".join(json.dumps({"key": e.key()}) for e in (events or dataset())))
    spec = ExternalHoldoutSpec(
        train_domain="UNSW-NB15", holdout_domain="CIC-IDS2017",
        training_sha256="a" * 64,
        holdout_sha256=hashlib.sha256(corpus.read_bytes()).hexdigest(),
        model_sha256=hashlib.sha256(model.read_bytes()).hexdigest(),
        acquisition_statement="Original approved independently sourced capture",
        label_provenance="Independent security analyst reviewed labels",
        independent_capture_attested=True,
        max_false_positive_rate=.08, min_true_positive_rate=.9,
        min_benign=100, min_attack=50, min_capture_days=3,
    )
    return model, corpus, spec


def eval_run(tmp_path, events=None, training=None):
    records = events if events is not None else dataset()
    model, corpus, spec = case(tmp_path, records)
    return evaluate_frozen_holdout(
        spec=spec, model_path=model, corpus_path=corpus,
        records_factory=lambda: iter(records), detector_loader=lambda _: PerfectFrozenDetector(),
        training_keys=training if training is not None else TrainingLedger(
            frozenset({"f" * 32}), frozenset({"f" * 64})),
    )


def test_frozen_external_model_accepts_independent_multiday_perfect_fixture(tmp_path):
    out = eval_run(tmp_path)
    assert out["status"] == "passed"
    assert out["scope"].endswith("not_field_certification")
    assert out["unique_holdout_events"] == 360
    assert out["confusion_matrix"] == {"tp": 180, "tn": 180, "fp": 0, "fn": 0}
    assert out["false_positive_rate"] == 0
    assert out["average_precision"] == 1
    assert out["fpr_wilson_95"][1] > 0
    assert out["recall_wilson_95"][0] < 1
    assert out["capture_days_with_benign"] == 3
    assert len(out["per_day"]) == 3
    assert out["training_ids_overlap"] == 0


def test_training_holdout_overlap_fail_closed(tmp_path):
    events = dataset()
    with pytest.raises(ValueError, match="overlap"):
        eval_run(tmp_path, events, training=TrainingLedger(
            frozenset({events[0].key()}), frozenset({"f" * 64})))


def test_holdout_canonical_duplicate_fail_closed(tmp_path):
    events = dataset()
    events[-1].identifier = events[0].identifier
    with pytest.raises(ValueError, match="Duplicate canonical"):
        eval_run(tmp_path, events)


def test_refuse_synthetic_or_unlabeled_holdout(tmp_path):
    events = dataset()
    events[0].source = "simulator"
    with pytest.raises(ValueError, match="Synthetic simulator"):
        eval_run(tmp_path, events)
    events = dataset()
    events[0].label = None
    with pytest.raises(ValueError, match="independently labeled"):
        eval_run(tmp_path, events)


def test_insufficient_independent_days_fails_even_when_accuracy_perfect(tmp_path):
    events = dataset()
    for event in events:
        event.timestamp = events[0].timestamp
    report = eval_run(tmp_path, events)
    assert report["status"] == "failed"
    assert report["acceptance"]["min_days_met"] is False


def test_wrong_approved_model_digest_fails_before_loader(tmp_path):
    model, corpus, spec = case(tmp_path)
    model.write_bytes(b"different-unsigned-pickle")
    with pytest.raises(ValueError, match="pin mismatch"):
        evaluate_frozen_holdout(
            spec=spec, model_path=model, corpus_path=corpus,
            records_factory=lambda: iter(dataset()),
            detector_loader=lambda _: pytest.fail("Untrusted pickle was loaded"),
            training_keys=TrainingLedger(
                frozenset({"f" * 32}), frozenset({"f" * 64})),
        )


def test_training_ledger_sha_and_duplicates_are_mandatory(tmp_path):
    ledger = tmp_path / "training-ids.txt"
    ledger.write_text("a" * 32 + "\t" + "a" * 64 + "\n" +
                      "b" * 32 + "\t" + "b" * 64 + "\n")
    h = hashlib.sha256(ledger.read_bytes()).hexdigest()
    result = load_training_keys(ledger, h)
    assert result.canonical_ids == {"a" * 32, "b" * 32}
    assert result.normalized_fingerprints == {"a" * 64, "b" * 64}
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        load_training_keys(ledger, "0" * 64)
    ledger.write_text(("a" * 32 + "\t" + "a" * 64 + "\n") * 2)
    with pytest.raises(ValueError, match="Duplicate"):
        load_training_keys(ledger, hashlib.sha256(ledger.read_bytes()).hexdigest())


def test_wilson_bounds_and_immutable_evidence(tmp_path):
    low, high = wilson_interval(0, 100)
    assert low == 0 and 0 < high < .05
    with pytest.raises(ValueError):
        wilson_interval(11, 10)
    report = tmp_path / "evidence" / "run.json"
    write_evidence_once(report, {"status": "failed"})
    assert report.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        write_evidence_once(report, {"status": "passed"})
    assert json.loads(report.read_text())["status"] == "failed"


def test_same_flow_from_different_adapter_still_fails_overlap(tmp_path):
    events = dataset()
    normalized = normalized_flow_fingerprint(events[0])
    # Canonical ID differs, but source-neutral flow contents are identical.
    training = TrainingLedger(frozenset({"f" * 32}), frozenset({normalized}))
    with pytest.raises(ValueError, match="normalized-flow overlap"):
        eval_run(tmp_path, events, training=training)


def test_duplicate_same_holdout_flow_with_distinct_adapter_uid_rejected(tmp_path):
    events = dataset()
    original = events[0]
    events[-1] = Event(identifier="a" * 32, timestamp=original.timestamp,
                       label=original.label, source="zeek",
                       flow_port=1024 + int(original.identifier, 16) % 50000)
    with pytest.raises(ValueError, match="Duplicate normalized flow"):
        eval_run(tmp_path, events)
