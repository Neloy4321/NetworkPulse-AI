"""Contract v2: real missing is distinct from measured zero in both adapters."""
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from networkpulse.feature_contract_v2 import (
    V2_FEATURE_CONTRACT, FlowV2, features_v2, from_suricata_v2, from_zeek_v2,
)
from networkpulse.schemas import FlowEvent


def zeek(**kw):
    row = {
        "ts": 1767225600.25, "uid": "synthetic-uid",
        "id.orig_h": "192.0.2.10", "id.orig_p": 50400,
        "id.resp_h": "198.51.100.10", "id.resp_p": 443,
        "proto": "tcp", "conn_state": "S0",
        "duration": "0", "orig_bytes": "0", "resp_bytes": "0",
        "orig_pkts": "0", "resp_pkts": "0",
    }
    row.update(kw)
    return row


def test_explicit_missing_is_different_from_genuine_zero():
    missing = from_zeek_v2(zeek(
        duration="-", orig_bytes="-", resp_bytes=None,
        orig_pkts="-", resp_pkts=None
    ))
    zeros = from_zeek_v2(zeek())
    a, b = features_v2(missing), features_v2(zeros)
    assert missing.duration is None and zeros.duration == 0
    assert missing.resp_pkts is None and zeros.resp_pkts == 0
    assert a["missing_orig_bytes"] == 1
    assert b["missing_orig_bytes"] == 0
    assert a["missing_bytes_per_second"] == 1
    assert b["missing_bytes_per_second"] == 0
    assert a["missing_response_fraction"] == 1
    assert b["missing_response_fraction"] == 0
    assert a != b


def test_zero_missing_flags_and_ratios_are_finite_in_dense_vector():
    complete = from_zeek_v2(zeek(
        duration=2.0, orig_bytes=120, resp_bytes=240,
        orig_pkts=4, resp_pkts=8
    ))
    feat = features_v2(complete)
    assert len(feat) == 20  # 16 numeric+missing flags, two one-hots
    assert all(type(v) is float for v in feat.values())
    assert all(v >= 0 for v in feat.values())
    assert feat["missing_duration"] == 0.0
    assert feat["response_fraction"] == pytest.approx(2 / 3)
    assert feat["port_class=well_known"] == 1.0


def test_zeek_and_suricata_live_adapters_agree_when_counters_equivalent():
    zeek_result = from_zeek_v2(zeek(
        duration=2, orig_bytes=120, resp_bytes=240, orig_pkts=4, resp_pkts=8
    ))
    suricata_result = from_suricata_v2({
        "timestamp": "2026-01-01T00:00:00+00:00",
        "event_type": "flow", "flow_id": 1,
        "src_ip": "192.0.2.10", "dest_ip": "198.51.100.10",
        "src_port": 50400, "dest_port": 443, "proto": "TCP",
        "flow": {"age": 2, "bytes_toserver": 120, "bytes_toclient": 240,
                 "pkts_toserver": 4, "pkts_toclient": 8, "state": "established"},
    })
    assert features_v2(zeek_result) == features_v2(suricata_result)


def test_suricata_missing_values_preserved_not_zero_imputed():
    result = from_suricata_v2({
        "timestamp": "2026-01-01T00:00:00+00:00",
        "event_type": "flow", "src_ip": "192.0.2.10",
        "dest_ip": "198.51.100.10", "src_port": 50000,
        "dest_port": 443, "proto": "tcp",
        "flow": {"bytes_toserver": 0, "bytes_toclient": None},
    })
    assert result.orig_bytes == 0
    assert result.resp_bytes is None
    assert result.duration is None
    assert features_v2(result)["missing_orig_bytes"] == 0.0
    assert features_v2(result)["missing_resp_bytes"] == 1.0


@pytest.mark.parametrize("value", [-1, "nan", "inf", "1.2", True, "not-number"])
def test_negative_invalid_fractional_or_boolean_integer_fails(value):
    with pytest.raises((ValueError, ValidationError)):
        from_zeek_v2(zeek(orig_bytes=value))


def test_missing_port_and_timestamp_fail_closed():
    with pytest.raises(ValueError, match="port identity"):
        from_zeek_v2(zeek(**{"id.resp_p": "-"}))
    with pytest.raises((ValueError, KeyError)):
        from_zeek_v2(zeek(ts="-"))


def test_v1_contract_stays_strict_and_separate():
    assert V2_FEATURE_CONTRACT == "missingness_aware_flow_v2"
    old = FlowEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), source="canonical",
        src_ip="192.0.2.10", dst_ip="198.51.100.10", src_port=50000,
        dst_port=443, proto="tcp", duration=0, orig_bytes=0,
        resp_bytes=0, orig_pkts=0, resp_pkts=0,
    )
    with pytest.raises(TypeError, match="FlowV2 required"):
        features_v2(old)
    with pytest.raises(ValidationError):
        FlowV2.model_validate(old.model_dump() | {"orig_bytes": -1})


def test_invalid_flow_schema_and_unsupported_suricata_records_refused():
    with pytest.raises(ValueError, match="only Suricata EVE flow"):
        from_suricata_v2({"event_type": "alert"})
    with pytest.raises(ValidationError):
        FlowV2.model_validate({"timestamp": datetime.now(timezone.utc)})
