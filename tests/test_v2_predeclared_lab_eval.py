"""Pre-registered lab targets: strict natural support and immutable model."""
from pathlib import Path

import numpy as np
import pytest

from networkpulse.evaluation.v2_predeclared_lab_eval import (
    CAPTURES, REGISTERED, FROZEN_SOURCE_V2_SHA,
    parse_capture, score, evaluate,
)
from networkpulse.evaluation.v2_mixed_source_freeze import (
    PROTOCOL, protocol_digest, FIXED_CUTOFF,
)
from networkpulse.feature_contract_v2 import (
    V2_FEATURE_CONTRACT, from_zeek_v2,
)
from networkpulse.evaluation.iot23v2_source_adapter import COLUMNS, TRAILER


def row(i: int = 1, *, label: str = "Benign") -> str:
    cells = [
        str(1545403816.0 + i), f"fixture-{i}",
        "192.0.2.11", str(50000 + i), "198.51.100.20", "443",
        "tcp", "-", "-", "-", "-", "S0", "-", "-", "0",
        "S", "3", "180", "0", "0", "-   " + label + "   -",
    ]
    return "\t".join(cells) + "\n"


def header() -> str:
    return "#fields\t" + "\t".join(COLUMNS + (TRAILER,)) + "\n"


def test_two_targets_predeclared_before_scoring():
    assert REGISTERED == (
        "CTU-IoT-Malware-Capture-8-1",
        "CTU-IoT-Malware-Capture-20-1",
    )
    assert len(CAPTURES) == 2
    assert all(f.endswith("-zeek-conn-log.labeled") for f in CAPTURES.values())
    assert FROZEN_SOURCE_V2_SHA == (
        "a1b90b4f26b98cfa00b65fd218d90ef5af97e800cf636ecfe8fa5620be6c4589"
    )
    assert PROTOCOL["feature_contract"] == V2_FEATURE_CONTRACT
    assert len(protocol_digest()) == 64
    assert FIXED_CUTOFF == 0.5


def test_labeled_zeek_missing_bytes_is_scored_as_missing_not_zero(tmp_path: Path):
    path = tmp_path / "synthetic.labeled"
    path.write_text(header() + row(1) + row(2, label="Malicious"))
    events, labels, counts = parse_capture(path)
    assert len(events) == 2 and labels.tolist() == [0, 1]
    assert counts["benign"] == 1 and counts["malicious"] == 1
    assert counts["missing_numeric"] == 2
    assert all(event.duration is None for event in events)
    assert all(event.label is None for event in events)


def test_one_class_does_not_fabricate_numeric_quality_result():
    e = from_zeek_v2({
        "ts": 1545403816, "uid": "test",
        "id.orig_h": "192.0.2.11", "id.orig_p": 50000,
        "id.resp_h": "198.51.100.20", "id.resp_p": 443,
        "proto": "tcp", "conn_state": "S0",
    })
    fake_model = {
        "feature_contract": V2_FEATURE_CONTRACT, "schema_version": 2,
        "production_approved": False, "protocol_sha256": protocol_digest(),
        "fixed_cutoff": FIXED_CUTOFF,
    }
    result = score(fake_model, [e], np.asarray([0], dtype=int), {
        "benign": 1, "malicious": 0, "missing_numeric": 1,
    })
    assert result["status"] == "blocked_insufficient_natural_class_support"
    assert result["metrics"] is None
    assert result["quality_numeric_research_only"] is None


def test_unknown_attack_label_fails_closed(tmp_path: Path):
    path = tmp_path / "bad_label.log"
    path.write_text(header() + row(1, label="Unknown"))
    with pytest.raises(ValueError, match="unknown/ambiguous"):
        parse_capture(path)


def test_duplicate_capture_rows_refused(tmp_path: Path):
    path = tmp_path / "duplicated.log"
    path.write_text(header() + row(1) + row(1))
    with pytest.raises(ValueError, match="duplicate"):
        parse_capture(path)


def test_unknown_model_or_target_set_cannot_run(tmp_path: Path):
    with pytest.raises(ValueError, match="pre-registered"):
        evaluate(tmp_path / "model.joblib", tmp_path / "manifest.json", {})
    sources = {
        name: tmp_path / filename
        for name, filename in CAPTURES.items()
    }
    with pytest.raises((FileNotFoundError, ValueError)):
        evaluate(tmp_path / "model.joblib", tmp_path / "manifest.json", sources)


def test_workflow_enforces_exact_model_and_no_promotion():
    workflow = (Path(__file__).resolve().parents[1] /
                ".github/workflows/v2-predeclared-lab-eval.yml").read_text()
    assert "v2_predeclared_lab_eval" in workflow
    assert "CTU-IoT-Malware-Capture-8-1" in workflow
    assert "CTU-IoT-Malware-Capture-20-1" in workflow
    assert "production_model_signed_and_active" in workflow
