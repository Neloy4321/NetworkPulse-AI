"""Candidate release: canonical dataset integrity, leakage gates, lineage and immutability."""
from datetime import timedelta
from pathlib import Path

import pytest

from networkpulse.cli import main
from networkpulse.data_quality import fingerprint
from networkpulse.model_registry import ModelRegistry, sha256
from networkpulse.simulator import sample_flows
from networkpulse.training_release import (
    build_candidate, validate_training_input, verify_candidate,
)


def _ordered():
    return sample_flows(400, seed=23)


def _build(tmp_path, events=None, name="candidate-a"):
    return build_candidate(
        events if events is not None else _ordered(),
        name=name, root=tmp_path / "candidates",
        dataset_sha256="1" * 64, source_id="synthetic_dataset_ci_only",
        seed=12, min_boundary_gap_seconds=1.0,
    )


def test_release_lineage_metrics_checksum_and_registry_never_auto_promotes(tmp_path):
    first = _build(tmp_path)
    directory = Path(first["directory"])
    result = verify_candidate(directory)
    assert result["integrity"] == "verified_without_unpickling"
    assert result["sha256"] == sha256(Path(first["model_path"]))
    assert result["synthetic_only"] is True
    import json
    manifest = json.loads(Path(first["manifest_path"]).read_text())
    assert manifest["dataset"]["record_count"] == 400
    assert manifest["dataset"]["split_counts"]["holdout_total"] == 100
    assert manifest["dataset"]["split_counts"]["fit_benign"] >= 50
    assert manifest["dataset"]["source_authenticity_independently_verified"] is False
    assert manifest["release"]["state"] == "candidate_not_deployed"
    assert "src_ip" not in str(manifest) and "dst_ip" not in str(manifest)
    assert "10.11." not in str(manifest)
    with pytest.raises(FileExistsError):
        _build(tmp_path)
    another = _build(tmp_path, name="candidate-b")
    # Artifact bytes vary because trained_at is metadata. Predictions don't.
    assert first["functional_holdout_sha256"] == another["functional_holdout_sha256"]
    registry = ModelRegistry(tmp_path / "registry")
    record = registry.register(
        "candidate-a", Path(first["model_path"]), release_directory=directory,
    )
    assert record["release_lineage"]["raw_source_sha256"] == "1"*64
    assert record["release_lineage"]["input_identity_sha256"] == (
        manifest["dataset"]["event_identity_sha256"]
    )
    assert registry.status()["active"] is None
    with pytest.raises(ValueError, match="production"):
        registry.promote("candidate-a", tmp_path / "live-model.joblib", production=True)
    assert not (tmp_path / "live-model.joblib").exists()


def test_release_fails_closed_on_duplicates_order_gap_unknown_labels(tmp_path):
    samples = _ordered()
    with pytest.raises(ValueError, match="duplicate"):
        validate_training_input(samples[:120] + [samples[2]] + samples[121:])
    out_of_order = samples.copy()
    out_of_order[30], out_of_order[31] = out_of_order[31], out_of_order[30]
    with pytest.raises(ValueError, match="sorted"):
        validate_training_input(out_of_order)
    missing = samples.copy()
    missing[-1] = missing[-1].model_copy(update={"label": None})
    with pytest.raises(ValueError, match="labels"):
        _build(tmp_path, missing)
    tied = samples.copy()
    tied[240] = tied[240].model_copy(update={
        "timestamp": tied[239].timestamp,
    })
    with pytest.raises(ValueError, match="boundaries"):
        validate_training_input(tied)
    assert not (tmp_path / "candidates").exists()
    with pytest.raises(ValueError, match="row cap"):
        validate_training_input(samples, max_events=100)


def test_checksum_tampering_and_claimed_integrity_gate(tmp_path):
    built = _build(tmp_path)
    file = Path(built["model_path"])
    file.write_bytes(file.read_bytes() + b"tamper")
    with pytest.raises(ValueError, match="integrity"):
        verify_candidate(Path(built["directory"]))
    with pytest.raises(ValueError, match="integrity"):
        ModelRegistry(tmp_path / "registry").register(
            "candidate-a", file, release_directory=Path(built["directory"]),
        )


def test_cli_release_requires_exact_dataset_sha_and_never_overwrites(tmp_path, capsys):
    samples = _ordered()
    path = tmp_path / "authorized-flow-training.jsonl"
    path.write_text(
        "\n".join(event.model_dump_json() for event in samples) + "\n",
        encoding="utf-8",
    )
    args = [
        "train-release", "--data", str(path), "--dataset-sha256", fingerprint(path),
        "--source-id", "synthetic_test", "--name", "ci-training",
        "--root", str(tmp_path / "candidates"),
        "--registry-root", str(tmp_path / "registry"),
    ]
    assert main(args) == 0
    assert "candidate_not_deployed" in capsys.readouterr().out
    output = tmp_path / "candidates" / "ci-training"
    assert main(["verify-release", "--directory", str(output)]) == 0
    assert ModelRegistry(tmp_path / "registry").status()["active"] is None
    with pytest.raises(SystemExit):
        main([*args[:4], "0"*64, *args[5:]])
    with pytest.raises(FileExistsError):
        main(args)


def test_too_few_holdout_classes_rejected(tmp_path):
    events = _ordered()
    benign_holdout = [
        e.model_copy(update={"label": "benign"})
        for e in events[300:]
    ]
    with pytest.raises(ValueError, match="holdout classes"):
        _build(tmp_path, events[:300] + benign_holdout)


def test_separate_later_capture_gates_release_without_holdout_label_leakage(tmp_path):
    earlier = _ordered()
    # Preserve train/calibration history but deliberately make the *internal*
    # last quartile benign. A separately labeled later capture provides the
    # candidate evaluation. Do not weaken the data-quality gate silently.
    earlier = earlier[:300] + [
        e.model_copy(update={"label": "benign"}) for e in earlier[300:]
    ]
    later = sample_flows(
        320, seed=29,
        start=earlier[-1].timestamp + timedelta(days=1),
    )
    release = build_candidate(
        earlier, name="real-protocol-fixture", root=tmp_path/"separate",
        source_id="synthetic_test_earlier", dataset_sha256="1"*64,
        validation_events=later,
        validation_source_sha256="2"*64,
        validation_source_id="synthetic_test_later",
        seed=23,
    )
    import json
    manifest = json.loads(Path(release["manifest_path"]).read_text())
    assert manifest["separate_validation_capture"]["record_count"] == 320
    assert manifest["separate_validation_capture"]["same_site_independence_verified"] is False
    assert manifest["model"]["evaluation_protocol"] == "strictly_later_separate_capture"
    assert release["metrics"]["benign_count"] >= 20
    assert release["metrics"]["attack_count"] >= 5
    assert manifest["dataset"]["split_counts"]["holdout_anomaly"] == 0
    overlaps = later.copy()
    overlaps[0] = overlaps[0].model_copy(update={
        "timestamp": earlier[0].timestamp,
    })
    with pytest.raises(ValueError, match="overlaps training"):
        build_candidate(
            earlier, name="overlap", root=tmp_path/"separate",
            source_id="synthetic_test", dataset_sha256="1"*64,
            validation_events=overlaps,
            validation_source_sha256="2"*64,
            validation_source_id="synthetic_later",
        )
    assert not (tmp_path / "separate" / "overlap").exists()
