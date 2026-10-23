"""Synthetic tests for bounded *real-source-ready* provenance accounting."""
from __future__ import annotations

import json

import pytest

from networkpulse.evaluation import iot_sfc_v7_provenance_sample as audit


def _row(log_type="conn.log", attack="1", **changes):
    result = {
        "ts": "1743681600.0",
        "uid": "SENSITIVE_UID_NEVER_EXPORT",
        "orig_h": "192.0.2.10",
        "orig_p": "41234",
        "resp_h": "198.51.100.11",
        "resp_p": "443",
        "proto": "tcp",
        "log_type": log_type,
        "duration": "0.1",
        "orig_bytes": "100",
        "resp_bytes": "-",
        "orig_pkts": "2",
        "resp_pkts": "",
        "conn_state": "SF",
        "attack": attack,
        "type_of_attack": "secret-attack-name",
        "label_source": "secret-label-issuer",
        "window_id": "secret-window-key",
    }
    result.update(changes)
    return result


def test_counts_only_no_raw_ip_uid_or_attack_family_exported():
    rows = [
        _row(),
        _row(attack="0", type_of_attack="-", window_id="-"),
        _row(log_type="dns.log", attack="1"),
        _row(log_type="strange-sensitive-private-log-type", attack="notbinary"),
    ]
    out = audit.summarize_rows(iter(rows), max_rows=10)
    assert out["rows_inspected"] == 4
    assert out["log_types_aggregate"] == {
        "PRESENT_BUT_UNRECOGNIZED": 1,
        "conn.log": 2,
        "dns.log": 1,
    }
    assert out["conn_only_binary_label_literals_aggregate"] == {"0": 1, "1": 1}
    assert out["conn_adapter_outcomes"]["FLOW_V2_CANDIDATE_VALID"] == 2
    assert out["producer_label_outcomes_unverified"]["PRODUCER_1_UNVERIFIED"] == 1
    assert out["producer_label_outcomes_unverified"]["PRODUCER_0_UNVERIFIED"] == 1
    assert out["producer_label_outcomes_unverified"]["missing_window_id"] == 1
    assert out["candidate_missing_counter_counts"]["resp_bytes"] == 2
    assert out["candidate_missing_counter_counts"]["resp_pkts"] == 2
    assert not out["labels_independently_adjudicated"]
    assert not out["model_training_or_inference_performed"]
    blob = json.dumps(out)
    for secret in (
        "SENSITIVE_UID_NEVER_EXPORT", "192.0.2.10", "198.51.100.11",
        "secret-attack-name", "secret-label-issuer", "secret-window-key",
        "strange-sensitive-private-log-type",
    ):
        assert secret not in blob


def test_invalid_rows_and_unknown_binary_do_not_prove_labels():
    rows = [
        {None: "row_width_wrong"},
        _row(attack="Attack"),
        _row(ts="broken", attack="0"),
        _row(attack="1", window_id="-"),
    ]
    out = audit.summarize_rows(iter(rows), max_rows=10)
    assert out["invalid_row_column_count"] == 1
    assert out["source_binary_label_literals_aggregate"] == {
        "0": 1, "1": 1, "NOT_LITERAL_BINARY_0_OR_1": 1,
    }
    assert out["conn_adapter_outcomes"] == {
        "FLOW_V2_CANDIDATE_VALID": 2,
        "invalid_native_zeek_conn_values": 1,
    }
    assert out["producer_label_outcomes_unverified"] == {
        "PRODUCER_0_UNVERIFIED": 0,
        "invalid_binary_producer_label": 1,
        "missing_attack_provenance_fields": 1,
    } or (
        out["producer_label_outcomes_unverified"]["invalid_binary_producer_label"] == 1
        and out["producer_label_outcomes_unverified"][
            "missing_attack_provenance_fields"
        ] == 1
    )


@pytest.mark.parametrize("count", [0, -1, 200001, 1.5, "1000"])
def test_max_rows_rejected_when_not_bounded_integer(count):
    with pytest.raises(ValueError):
        audit.summarize_rows(iter([_row()]), max_rows=count)


def test_fixed_limit_prevents_unbounded_iteration():
    def rows():
        for _ in range(100):
            yield _row()
        raise AssertionError("unbounded iterator")
    result = audit.summarize_rows(rows(), max_rows=5)
    assert result["rows_inspected"] == 5


def test_missing_and_negative_flow_counters_fail_closed():
    rows = [
        _row(orig_pkts="-1"),
        _row(orig_pkts=""),
        _row(attack="1", label_source="-"),
    ]
    result = audit.summarize_rows(rows, max_rows=3)
    assert result["conn_adapter_outcomes"]["invalid_native_zeek_conn_values"] == 1
    assert result["conn_adapter_outcomes"]["FLOW_V2_CANDIDATE_VALID"] == 2
    assert result["producer_label_outcomes_unverified"][
        "missing_attack_provenance_fields"
    ] == 1
    assert result["candidate_missing_counter_counts"]["orig_pkts"] == 1


def test_no_unknown_source_log_names_leak_to_aggregate():
    result = audit.summarize_rows([_row(log_type="confidential-logs-123")])
    assert result["log_types_aggregate"] == {"PRESENT_BUT_UNRECOGNIZED": 1}
    assert result["conn_adapter_outcomes"] == {}


def test_development_labels_not_used_for_training_or_prediction():
    out = audit.summarize_rows([_row()])
    assert out["not_an_unbiased_dataset_prevalence_estimate"]
    assert not out["numerical_ml_acceptance_calculated"]
    assert not out["labels_independently_adjudicated"]


def test_known_short_source_aliases_are_reported_but_not_promoted():
    result = audit.summarize_rows(
        [_row(log_type="conn"), _row(log_type="dns"), _row(log_type="CONN")]
    )
    assert result["log_types_aggregate"] == {"conn": 2, "dns": 1}
    assert result["conn_adapter_outcomes"] == {}
    assert result["not_exact_conn_log_count"] == 3


def test_empty_log_type_not_confused_with_unrecognized_nonempty():
    result = audit.summarize_rows([
        _row(log_type=""), _row(log_type="-"),
        _row(log_type="secret-private-logs"),
    ])
    assert result["log_types_aggregate"] == {
        "MISSING_OR_PLACEHOLDER": 2,
        "PRESENT_BUT_UNRECOGNIZED": 1,
    }
