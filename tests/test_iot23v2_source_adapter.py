"""Synthetic format fixtures only. Never claim official dataset evaluation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from networkpulse.evaluation.iot23v2_source_adapter import (
    COLUMNS, TRAILER, MissingNativeFeature, inspect_and_convert,
    parse_labeled_line, _require_header,
)


def header():
    return "#fields\t" + "\t".join(COLUMNS + (TRAILER,)) + "\n"


def zeek_flow(i: int, *, malicious: bool = False, missing: str = "") -> str:
    values = [
        str(1545403816.96 + i),
        f"zeekfixture-{i}",
        "192.0.2.10",
        str(20000 + i),
        "198.51.100.20",
        "443",
        "tcp",
        "-",
        "2.5",
        "120",
        "240",
        "SF",
        "-",
        "-",
        "0",
        "ShADad",
        "4",
        "300",
        "6",
        "350",
        "-   " + ("Malicious" if malicious else "Benign") +
        "   " + ("C&C" if malicious else "-"),
    ]
    if missing:
        values[COLUMNS.index(missing)] = "-"
    return "\t".join(values) + "\n"


def test_original_compound_label_and_required_sensor_coordinates():
    ev = parse_labeled_line(zeek_flow(1, malicious=True))
    assert ev.source == "zeek"
    assert ev.label == "anomaly"
    assert ev.proto == "tcp"
    assert ev.conn_state == "sf"
    assert ev.orig_bytes == 120
    assert ev.resp_pkts == 6
    assert ev.duration == 2.5
    assert ev.dst_port == 443


def test_missing_core_coordinates_are_not_zero_imputed():
    for field in (
        "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    ):
        with pytest.raises(MissingNativeFeature):
            parse_labeled_line(zeek_flow(2, missing=field))


def test_unknown_labels_and_malformed_tab_layout_fail_closed():
    with pytest.raises(ValueError, match="ambiguous IoT-23 label"):
        parse_labeled_line(zeek_flow(1).replace("Benign", "Unknown"))
    with pytest.raises(ValueError, match="column count"):
        parse_labeled_line("this is not a Zeek row")
    with pytest.raises(ValueError, match="independent label trailer"):
        parse_labeled_line(zeek_flow(1).replace("-   Benign   -", "-"))


def test_schema_pinning_rejects_altered_zeek_columns():
    _require_header(header())
    with pytest.raises(ValueError, match="unknown IoT-23v2"):
        _require_header(header().replace("orig_bytes", "orig_ip_bytes2"))
    with pytest.raises(ValueError, match="#fields"):
        _require_header("ts\tuid\n")


def test_complete_case_conversion_is_aggregate_only(tmp_path: Path):
    source = tmp_path / "untrusted-lab-file.labeled"
    rows = [zeek_flow(i, malicious=(i >= 230)) for i in range(360)]
    rows[9] = zeek_flow(9, missing="duration")
    source.write_text(
        "#separator \\x09\n" + header() + "".join(rows), encoding="utf-8"
    )
    output = tmp_path / "private-raw-canonical.jsonl"
    report = tmp_path / "aggregate-only.json"
    result = inspect_and_convert(source, output, report)
    assert result["status"] == "iot23v2_schema_conversion_only"
    assert result["converted_labeled_rows"] == 359
    assert result["excluded_missing_native_values"] == 1
    assert result["benign_complete_rows"] == 229
    assert result["attack_complete_rows"] == 130
    assert result["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert result["canonical_sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
    assert result["sensor_missing_values_were_imputed"] is False
    assert result["operational_ml_acceptance_demonstrated"] is False
    assert output.stat().st_mode & 0o777 == 0o600
    assert "192.0.2." not in report.read_text()
    assert "198.51.100." not in report.read_text()
    canon = [json.loads(x) for x in output.read_text().splitlines()]
    assert len(canon) == 359 and canon[-1]["label"] == "anomaly"
    with pytest.raises(ValueError, match="refusing overwrite"):
        inspect_and_convert(source, output, report)


def test_inadequate_attack_support_fails_without_publishing_target(tmp_path: Path):
    source = tmp_path / "no-valid-attack.labeled"
    source.write_text(header() + "".join(
        zeek_flow(i, malicious=(i >= 220)) for i in range(240)
    ))
    target = tmp_path / "canonical.jsonl"
    report = tmp_path / "metadata.json"
    with pytest.raises(ValueError, match="class coverage insufficient"):
        inspect_and_convert(source, target, report)
    assert not target.exists()
    assert not target.with_name(target.name + ".partial").exists()
    assert not report.exists()


def test_bad_source_schema_rejects_without_output(tmp_path: Path):
    path = tmp_path / "bad.txt"
    path.write_text(header().replace("conn_state", "conn_something_else") +
                    zeek_flow(1))
    with pytest.raises(ValueError, match="unknown IoT-23v2"):
        inspect_and_convert(path, tmp_path / "out.jsonl", tmp_path / "out.json")


def test_workflow_only_runs_synthetic_contract_checks():
    workflow = (Path(__file__).resolve().parents[1] /
                ".github/workflows/iot23v2-schema-preflight.yml").read_text()
    assert "test_iot23v2_source_adapter.py" in workflow
    assert "R2_SECRET_ACCESS_KEY" not in workflow
    assert "source-only-research-model" not in workflow
    assert "curl" not in workflow
