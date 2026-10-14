"""Regression coverage for the operational SQL behavior API (no accuracy claims)."""
from datetime import datetime, timezone

import pytest

from networkpulse.behavior import activity_windows
from networkpulse.schemas import FlowEvent
from networkpulse.service import ingest
from networkpulse.storage import build_sessions


def _events(sample):
    source = sample.model_dump(mode="json")
    events = []
    for minute, second, port, target in (
        (0, 10, 80, "203.0.113.10"),
        (0, 20, 81, "203.0.113.11"),
        (1, 1, 80, "203.0.113.10"),
        (4, 59, 443, "203.0.113.12"),
        (5, 0, 443, "203.0.113.10"),
    ):
        row = {**source,
               "timestamp": datetime(2026, 10, 14, 12, minute, second,
                                     tzinfo=timezone.utc).isoformat(),
               "src_ip": "198.51.100.7", "dst_ip": target,
               "dst_port": port, "source": "canonical"}
        events.append(FlowEvent.model_validate(row))
    return events


def test_operational_windows_sql_exact_counts_utc_and_idempotency(
        client, app_settings, trained_detector, samples):
    events = _events(samples[0])
    maker = build_sessions(app_settings.database_url)
    anchor = datetime(2026, 10, 14, 12, 6, tzinfo=timezone.utc)
    try:
        with maker() as session:
            first = ingest(session, trained_detector, events)
            repeated = ingest(session, trained_detector, events)
            assert first["inserted"] == 5
            assert repeated["inserted"] == 0 and repeated["duplicates"] == 5
            one = activity_windows(session, window_minutes=1, until=anchor,
                                   lookback_minutes=10, min_distinct_ports=2,
                                   min_distinct_destinations=2)
            five = activity_windows(session, window_minutes=5, until=anchor,
                                    lookback_minutes=10, min_distinct_ports=2,
                                    min_distinct_destinations=2)
            assert [w["flow_count"] for w in one["windows"]] == [1, 1, 1, 2]
            assert [w["flow_count"] for w in five["windows"]] == [1, 4]
            assert sum(w["flow_count"] for w in five["windows"]) == 5
            bucket = five["windows"][1]
            assert bucket["distinct_destination_ports"] == 3
            assert bucket["distinct_destination_hosts"] == 3
            assert {"port_sweep_like", "destination_fanout_like"} <= set(bucket["patterns"])
            assert one["windows"][-1]["window_start_utc"] == "2026-10-14T12:00:00+00:00"
            assert five["windows"][0]["partial_window"] is True
            assert five["windows"][1]["partial_window"] is False
            assert activity_windows(session, until=anchor, lookback_minutes=10,
                                    src_ip="198.51.100.55")["windows"] == []
            paged = activity_windows(session, until=anchor, lookback_minutes=10, limit=1)
            assert paged["has_more"] is True
            with pytest.raises(ValueError, match="timezone"):
                activity_windows(session, until=anchor.replace(tzinfo=None))
    finally:
        maker.kw["bind"].dispose()

    path = "/api/v1/intelligence/behavior"
    params = {"until": anchor.isoformat(), "lookback_minutes": 10, "window_minutes": 1}
    answer = client.get(path, params=params)
    assert answer.status_code == 200
    assert sum(w["flow_count"] for w in answer.json()["windows"]) == 5
    for invalid in (
        {"window_minutes": 2},
        {"lookback_minutes": 1441},
        {"src_ip": "not-an-ip"},
        {"until": "2026-10-14T12:06:00"},
        {"limit": 200},
    ):
        assert client.get(path, params=invalid).status_code == 422
