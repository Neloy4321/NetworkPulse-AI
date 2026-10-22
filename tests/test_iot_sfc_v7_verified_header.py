"""Regression contract for real 87-column IoT-SFC v7 header-only evidence."""
from __future__ import annotations

import json
from pathlib import Path

from networkpulse.evaluation.iot_sfc_preregistration import MODEL_SHA, TARGET_SHA
from networkpulse.evaluation.iot_sfc_schema_audit import classify_header


EVIDENCE = Path(__file__).resolve().parents[1] / (
    "docs/P0_IOT_SFC_V2_VERIFIED_HEADER_EVIDENCE.json"
)


def test_actual_official_87_column_schema_is_pinned():
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    columns = evidence["csv_header_exact"]
    assert len(columns) == 87
    assert len(set(columns)) == 87
    assert evidence["csv_header_count"] == 87
    assert evidence["source_original_sha256"] == TARGET_SHA
    assert evidence["model_sha256"] == MODEL_SHA
    assert evidence["decision_threshold"] == 0.2
    assert evidence["full_zip_sha256_verified"] is True
    assert evidence["zip_member_crc_verified"] is False
    assert evidence["csv_data_rows_read"] is False
    assert evidence["candidate_label_values_verified"] is False
    assert evidence["rights_verified"] is False
    assert evidence["model_scored"] is False
    assert evidence["p0_operational_ml_acceptance"] == "NO_GO"


def test_actual_v7_aliases_are_not_silently_accepted_as_zeek():
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    result = classify_header(evidence["csv_header_exact"])
    assert result["header_only_schema_status"].startswith("BLOCKED")
    assert result["required_zeek_conn_missing"] == [
        "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"
    ]
    assert result["possible_unverified_aliases"] == {
        "id.orig_h": ["orig_h"],
        "id.orig_p": ["orig_p"],
        "id.resp_h": ["resp_h"],
        "id.resp_p": ["resp_p"],
    }
    assert "attack" in result["possible_label_columns"]
    assert "type_of_attack" in result["possible_label_columns"]
    assert result["possible_log_source_columns"] == ["log_type"]
    assert result["flow_direction_semantics_verified"] is False
    assert result["per_flow_labels_verified"] is False
    assert result["accepted_for_model_scoring"] is False
