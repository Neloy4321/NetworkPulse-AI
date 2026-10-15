"""Canonical, immutable training-key ledger tests with isolated fixtures."""
import hashlib
from types import SimpleNamespace

import pytest

from tools import export_training_id_ledger as exporter


def test_original_training_data_digest_enforced_before_parsing(monkeypatch, tmp_path):
    f = tmp_path / "source.jsonl"
    f.write_text("fixtures")
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        exporter.export_training_ledger(f, "0" * 64, tmp_path / "out.txt",
                                        reader=lambda *_: pytest.fail("Read before SHA"))


def test_export_training_id_ledger_is_sorted_private_and_no_overwrite(monkeypatch, tmp_path):
    f = tmp_path / "train.jsonl"
    f.write_text("approved corpus bytes")
    digest = hashlib.sha256(f.read_bytes()).hexdigest()
    examples = [SimpleNamespace(key=lambda k=k: k,
        model_dump=lambda **_: {"record": "metadata"})
        for k in ("2" * 32, "1" * 32)]
    destination = tmp_path / "audit" / "keys.txt"
    result = exporter.export_training_ledger(f, digest, destination,
                                             reader=lambda *_: iter(examples))
    lines = destination.read_text().splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("1" * 32 + "\t")
    assert lines[1].startswith("2" * 32 + "\t")
    assert destination.stat().st_mode & 0o777 == 0o600
    assert result["training_events"] == 2
    with pytest.raises(FileExistsError):
        exporter.export_training_ledger(f, digest, destination,
                                        reader=lambda *_: iter(examples))


def test_export_training_id_ledger_refuses_duplicates(monkeypatch, tmp_path):
    f = tmp_path / "train.jsonl"
    f.write_text("approved")
    digest = hashlib.sha256(f.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="Duplicate"):
        exporter.export_training_ledger(f, digest, tmp_path / "out.txt",
            reader=lambda *_: iter([SimpleNamespace(key=lambda: "1" * 32,
        model_dump=lambda **_: {"record": "metadata"}),
                                     SimpleNamespace(key=lambda: "1" * 32,
        model_dump=lambda **_: {"record": "metadata"})]))


def test_original_training_corpus_must_reconstruct_exact_ledger(tmp_path):
    import json
    from networkpulse.generalization_evidence import verify_training_source_ledger
    from networkpulse.simulator import sample_flows

    source = tmp_path / "original.jsonl"
    flows = sample_flows(count=120, seed=2026)
    source.write_text("".join(json.dumps(event.model_dump(mode="json")) + "\n"
                              for event in flows))
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    ledger = tmp_path / "ledger.tsv"
    report = exporter.export_training_ledger(source, digest, ledger)
    assert verify_training_source_ledger(source, digest, report["ledger_sha256"]) == 120
    with pytest.raises(ValueError, match="do not match"):
        verify_training_source_ledger(source, digest, "b" * 64)
