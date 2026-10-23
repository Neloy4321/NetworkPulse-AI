"""Fail-closed IoT-SFC v7 adapter tests; all rows below are synthetic fixtures."""
from __future__ import annotations


import pytest

from networkpulse.evaluation.iot_sfc_v7_conn_adapter import (
    HEADER_EVIDENCE, RowNotEligible, conn_log_to_flow_v2,
    inspect_untrusted_producer_label, verify_exact_header,
)
from networkpulse.feature_contract_v2 import features_v2, from_zeek_v2


def fixture_row():
    return {
        "ts": "1743681600.0", "uid": "synthetic-fixture-1",
        "orig_h": "192.0.2.10", "orig_p": "41234",
        "resp_h": "198.51.100.11", "resp_p": "443",
        "proto": "tcp", "log_type": "conn.log",
        "duration": "0.1", "orig_bytes": "100",
        "resp_bytes": "-", "orig_pkts": "2", "resp_pkts": "",
        "conn_state": "SF", "attack": "1",
        "type_of_attack": "synthetic-example",
        "label_source": "synthetic-fixture",
        "window_id": "test-window",
        "query": "not-a-flow-feature",
    }


def test_authentic_87_column_names_are_exactly_pinned():
    import json
    columns = json.loads(HEADER_EVIDENCE.read_text())["csv_header_exact"]
    audit = verify_exact_header(columns)
    assert audit["header_locked"]
    assert not audit["sensor_row_semantics_confirmed"]
    assert not audit["producer_labels_independently_reviewed"]
    assert audit["fixed_threshold"] == 0.20


def test_reordered_changed_or_dropped_column_blocked():
    import json
    cols = json.loads(HEADER_EVIDENCE.read_text())["csv_header_exact"]
    for broken in [cols[:-1], cols[::-1], [*cols[:-1], "renamed"]]:
        with pytest.raises(ValueError, match="pin mismatch"):
            verify_exact_header(broken)


def test_exact_native_zeek_feature_parity_on_synthetic_row():
    row = fixture_row()
    mapped = conn_log_to_flow_v2(row)
    native = {
        "ts": row["ts"], "uid": row["uid"],
        "id.orig_h": row["orig_h"], "id.orig_p": row["orig_p"],
        "id.resp_h": row["resp_h"], "id.resp_p": row["resp_p"],
        "proto": row["proto"], "duration": row["duration"],
        "orig_bytes": row["orig_bytes"], "resp_bytes": row["resp_bytes"],
        "orig_pkts": row["orig_pkts"], "resp_pkts": row["resp_pkts"],
        "conn_state": row["conn_state"],
    }
    expected = from_zeek_v2(native)
    assert mapped.model_dump() == expected.model_dump()
    assert features_v2(mapped) == features_v2(expected)
    assert mapped.label is None
    assert features_v2(mapped)["missing_resp_bytes"] == 1.0
    assert features_v2(mapped)["missing_resp_pkts"] == 1.0
    assert all("attack" not in name and "query" not in name for name in features_v2(mapped))


@pytest.mark.parametrize("value", [
    "dns.log", "http.log", "mqtt_publish.log", "weird.log",
    "conn", "CONN.LOG", "", None,
])
def test_non_exact_conn_event_is_never_coerced(value):
    row = fixture_row()
    row["log_type"] = value
    with pytest.raises(RowNotEligible, match="not_explicit_conn_log"):
        conn_log_to_flow_v2(row)


@pytest.mark.parametrize("name,value", [
    ("ts", "not-a-timestamp"),
    ("orig_h", "not-a-real-ip"),
    ("orig_p", "100.5"),
    ("resp_p", ""),
    ("proto", ""),
    ("duration", "-1"),
    ("orig_bytes", "3.14159"),
    ("resp_pkts", "bad"),
])
def test_invalid_telemetry_fails_closed(name, value):
    row = fixture_row()
    row[name] = value
    with pytest.raises(RowNotEligible):
        conn_log_to_flow_v2(row)


def test_required_field_absence_and_duplicate_native_mixed_schema_fails():
    row = fixture_row()
    del row["resp_h"]
    with pytest.raises(RowNotEligible, match="missing_required_column"):
        conn_log_to_flow_v2(row)
    row = fixture_row()
    row["id.orig_h"] = "203.0.113.55"
    with pytest.raises(RowNotEligible, match="ambiguous"):
        conn_log_to_flow_v2(row)


def test_missing_optional_counters_stay_none_not_fake_zeros():
    row = fixture_row()
    for key in ("duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"):
        row.pop(key, None)
    flow = conn_log_to_flow_v2(row)
    assert all(getattr(flow, key) is None for key in (
        "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"
    ))


def test_unreviewed_label_never_enters_flow_features():
    row = fixture_row()
    a = conn_log_to_flow_v2(row)
    row["attack"] = "0"
    row["type_of_attack"] = "some-text"
    b = conn_log_to_flow_v2(row)
    assert features_v2(a) == features_v2(b)
    assert a.label is None and b.label is None


def test_binary_producer_label_only_carries_unreviewed_status():
    evidence = inspect_untrusted_producer_label(fixture_row())
    assert evidence.producer_class == 1
    assert evidence.attack_family_present
    assert not evidence.independently_reviewed
    assert not evidence.independence_confirmed


@pytest.mark.parametrize("field,value", [
    ("attack", "Attack"),
    ("attack", "2"),
    ("type_of_attack", ""),
    ("label_source", ""),
    ("window_id", "-"),
])
def test_untrusted_attack_label_missing_or_nonnumeric_is_rejected(field, value):
    row = fixture_row()
    row[field] = value
    with pytest.raises(RowNotEligible):
        inspect_untrusted_producer_label(row)


def test_benign_can_have_no_attack_window_but_is_never_verified():
    row = fixture_row()
    row["attack"] = "0"
    row["type_of_attack"] = "-"
    row["window_id"] = "-"
    evidence = inspect_untrusted_producer_label(row)
    assert evidence.producer_class == 0
    assert evidence.independently_reviewed is False
