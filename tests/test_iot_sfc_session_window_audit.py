"""Attack-session hash, privacy and window semantics smoke tests."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from networkpulse.evaluation import iot_sfc_session_window_audit as audit


RAW = b'''# dataset metadata comment
[
 {"attack_type":"mqtt_malformed","start_time_utc":"2025-04-15 10:00:00Z",
  "end_time_utc":"2025-04-15 10:05:00Z","source":"192.0.2.8",
  "destinations":["198.51.100.2"]}
]'''


def test_comment_prefixed_json_and_aggregate_only_semantics():
    sessions = audit.parse_sessions(RAW)
    c = audit.Corroborator(sessions)
    c.observe_attack(family="mqtt_malformed",
                     timestamp=datetime(2025, 4, 15, 10, 3, tzinfo=timezone.utc),
                     src_ip="192.0.2.8", dst_ip="198.51.100.2")
    c.observe_attack(family="mqtt_malformed",
                     timestamp=datetime(2025, 4, 15, 10, 10, tzinfo=timezone.utc),
                     src_ip="192.0.2.10", dst_ip="198.51.100.20")
    result = c.aggregate_only()
    assert result["producer_labels_independently_adjudicated"] is False
    assert result["attack_window_match_is_ground_truth"] is False
    assert result["aggregate_counts"]["same_family_time_window"] == 1
    assert result["aggregate_counts"]["no_same_family_time_window"] == 1
    assert "192.0.2.8" not in str(result)


def test_reject_negative_windows_and_unknown_attack_types():
    with pytest.raises(ValueError, match="Negative"):
        audit.parse_sessions(RAW.replace(b"10:05:00Z", b"09:05:00Z"))
    with pytest.raises(ValueError, match="Unexpected attack family"):
        audit.parse_sessions(RAW.replace(b"mqtt_malformed", b"undocumented"))


def test_fail_closed_official_sha_guard(tmp_path):
    path = tmp_path / "unverified.json"
    path.write_bytes(RAW)
    with pytest.raises(ValueError, match="hash mismatch"):
        audit.load_exact_official_log(path)
