"""Tests for privacy-preserving IoT-SFC ZIP header-only adapter audit."""
from __future__ import annotations

import csv
import io
from types import SimpleNamespace

import pytest

from networkpulse.evaluation import iot_sfc_schema_audit as audit


def _header(*extra: str) -> bytes:
    columns = [*audit.REQUIRED_ZEEK_CONN, "log_type", "label", *extra]
    return (",".join(columns) + "\n").encode("ascii")


def test_header_only_strict_parse():
    parsed = audit._canonical_columns(_header("orig_bytes", "resp_bytes"))
    assert parsed[:6] == list(audit.REQUIRED_ZEEK_CONN)
    assert audit.classify_header(parsed)["accepted_for_model_scoring"] is False


@pytest.mark.parametrize("body", [
    b"", b"a,b", b"a,b\x00\n", b"a,a\n", b"a,\n", b"\xff,b\n",
    b"x" * (audit.MAX_HEADER_BYTES + 1),
    b'"column\nname",foo\n',
])
def test_malformed_or_large_header_rejected(body):
    with pytest.raises((ValueError, UnicodeDecodeError, csv.Error)):
        audit._canonical_columns(body)


def test_missing_source_discriminator_blocks_even_when_all_conn_fields_present():
    columns = list(audit.REQUIRED_ZEEK_CONN) + ["label"] + [
        f"c{i}" for i in range(80)
    ]
    assert len(columns) == 87
    status = audit.classify_header(columns)
    assert status["header_only_schema_status"].startswith("BLOCKED")
    assert not status["conn_log_row_filter_verified"]


def test_aliases_never_automatically_count_as_conn_fields():
    columns = list(audit.POTENTIAL_ALIASES.values())
    flat = [c[0] for c in columns] + ["log_type", "label"]
    flat += [f"extra{i}" for i in range(87 - len(flat))]
    status = audit.classify_header(flat)
    assert status["required_zeek_conn_exact_present"] == []
    assert status["possible_unverified_aliases"]["id.orig_h"] == ["src_ip"]
    assert status["accepted_for_model_scoring"] is False


def test_87_columns_with_exact_conn_fields_still_not_ready_for_scoring():
    columns = list(audit.REQUIRED_ZEEK_CONN) + ["log_type", "label"]
    columns += [f"x{i}" for i in range(87 - len(columns))]
    result = audit.classify_header(columns)
    assert result["header_only_schema_status"] == (
        "HEADER_FIELDS_PRESENT_ROW_SEMANTICS_UNVERIFIED"
    )
    assert result["per_flow_labels_verified"] is False
    assert result["flow_direction_semantics_verified"] is False
    assert result["accepted_for_model_scoring"] is False


def test_wrong_column_count_is_blocked():
    result = audit.classify_header(list(audit.REQUIRED_ZEEK_CONN) + ["log_type", "label"])
    assert result["column_count"] == 8
    assert result["header_only_schema_status"].startswith("BLOCKED")


def test_wrong_zip_size_or_symlink_rejected(tmp_path):
    target = tmp_path / "iot_dataset_v7.zip"
    target.write_bytes(b"not a ZIP")
    with pytest.raises(ValueError, match="byte length"):
        audit.audit_archive(target)
    link = tmp_path / "alias.zip"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        audit.audit_archive(link)


def test_zip_header_read_only_no_payload_record_read(monkeypatch, tmp_path):
    target = tmp_path / "iot_dataset_v7.zip"
    target.write_bytes(b"fake encrypted bytes that are never interpreted")
    monkeypatch.setattr(audit, "TARGET_SIZE", target.stat().st_size)
    monkeypatch.setattr(
        audit, "_digest", lambda _: (audit.TARGET_SHA, audit.EXPECTED_ARCHIVE_MD5)
    )
    class GuardStream:
        def readline(self, limit):
            assert limit == audit.MAX_HEADER_BYTES + 1
            return _header(*[f"extra{i}" for i in range(79)])
        def read(self, *_):
            raise AssertionError("Row/label values must never be read")
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return None

    class GuardZip:
        def __init__(self, *_args, **_kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return None
        def infolist(self):
            return [SimpleNamespace(
                filename="iot_dataset_v7.csv", flag_bits=0,
                file_size=13561863941, compress_type=audit.zipfile.ZIP_DEFLATED,
                external_attr=0,
                is_dir=lambda: False,
            )]
        def open(self, *_args, **_kwargs):
            return GuardStream()
    monkeypatch.setattr(audit.zipfile, "ZipFile", GuardZip)
    result = audit.audit_archive(target)
    assert result["archive_sha256_verified_from_original_bytes"]
    assert result["csv_header_read"]
    assert result["csv_data_rows_read"] is False
    assert result["label_values_read"] is False
    assert result["model_predictions_generated"] is False
    assert result["legal_reuse_rights_confirmed"] is False
    assert result["operational_ml_acceptance"] == "NO_GO"
    assert result["schema"]["accepted_for_model_scoring"] is False
