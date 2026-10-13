"""Queue visibility uses bounded stream metadata, never flow payloads."""

from networkpulse.observability import observe_stream
from networkpulse.streaming.monitoring import stream_snapshot


class FakeRedis:
    def __init__(self, *, group=True, has_stream=True, lag=3):
        self.group = group
        self.has_stream = has_stream
        self.lag = lag

    def xlen(self, key):
        return 4 if key.endswith(":stream") else 2

    def exists(self, key):
        return int(self.has_stream)

    def xinfo_groups(self, key):
        return [{"name": "other", "pending": 99, "lag": 99, "consumers": 7}] + (
            [{"name": "networkpulse-workers", "pending": 1,
              "lag": self.lag, "consumers": 2}] if self.group else []
        )


def test_stream_snapshot_reports_pending_and_lag_separately():
    result = stream_snapshot(FakeRedis())
    assert result == {
        "stream_depth": 4, "dead_letter_depth": 2,
        "pending": 1, "lag": 3, "consumers": 2, "group_exists": True,
    }


def test_absent_group_does_not_invent_zero_lag():
    assert stream_snapshot(FakeRedis(group=False))["lag"] is None
    assert stream_snapshot(FakeRedis(has_stream=False))["group_exists"] is False


def test_stream_prometheus_gauges():
    observe_stream("", client=FakeRedis())
    from networkpulse.observability import exporter

    data = exporter().body.decode()
    assert "networkpulse_stream_pending 1.0" in data
    assert "networkpulse_stream_lag 3.0" in data
    assert "networkpulse_stream_dead_letter_depth 2.0" in data
    assert "networkpulse_stream_redis_reachable 1.0" in data
