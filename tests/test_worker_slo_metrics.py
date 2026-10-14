"""Operational worker SLI correctness, graceful stop, and non-blocking telemetry."""
import pytest
from prometheus_client import generate_latest

from networkpulse.streaming import worker_metrics
from networkpulse.streaming.redis_streams import process_events


def sample_value(name):
    for sample in worker_metrics.QUEUE_RESIDENCE_SECONDS.collect()[0].samples:
        if sample.name == name:
            return sample.value
    raise AssertionError(name)


def test_ack_residence_uses_redis_server_time_and_no_sensitive_labels():
    class RedisClock:
        def time(self):
            return 1000, 500000

    before_count = sample_value("networkpulse_worker_queue_residence_seconds_count")
    before_sum = sample_value("networkpulse_worker_queue_residence_seconds_sum")
    worker_metrics.record_acknowledged(RedisClock(), ["999000-0", "1000000-1"])
    assert sample_value("networkpulse_worker_queue_residence_seconds_count") == before_count + 2
    assert sample_value("networkpulse_worker_queue_residence_seconds_sum") == pytest.approx(
        before_sum + 2.0
    )
    export = generate_latest().decode()
    assert "networkpulse_worker_queue_residence_seconds_bucket" in export
    assert "networkpulse_worker_batch_processing_seconds_bucket" in export
    assert "999000-0" not in export
    assert "src_ip=" not in export


@pytest.mark.parametrize("port", [-1, 0, 1023, 65536])
def test_metrics_binding_refuses_out_of_range_port(port):
    with pytest.raises(ValueError, match="port"):
        worker_metrics.start_private_exporter(port)


def test_graceful_shutdown_leaves_inflight_batch_completed(app_settings, monkeypatch):
    stopped = [False]
    cycles = []

    class CommittingQueue:
        def initialize(self):
            cycles.append("initialized")

        def consume_batch_once(self, *_args, **_kwargs):
            cycles.append("processed_and_acked")
            stopped[0] = True
            return {"processed": 5, "retried": 0, "dead_lettered": 0}

    heartbeats = []
    monkeypatch.setattr("networkpulse.ops_health.mark_success",
                        lambda *args: heartbeats.append(args))
    result = process_events(
        CommittingQueue(), "ci-graceful", settings=app_settings,
        stop_requested=lambda: stopped[0],
    )
    assert result is None
    assert cycles == ["initialized", "processed_and_acked"]
    assert len(heartbeats) == 1
    assert worker_metrics.WORKER_READY._value.get() == 0


def test_already_stopped_worker_does_not_claim_new_flows(app_settings):
    class Queue:
        consumed = False

        def initialize(self):
            pass

        def consume_batch_once(self, *_args, **_kwargs):
            self.consumed = True
            raise AssertionError("Must not claim messages after shutdown")

    queue = Queue()
    assert process_events(queue, "ci-prestopped", settings=app_settings,
                          stop_requested=lambda: True) is None
    assert not queue.consumed


def test_batch_outcome_metrics_are_bounded_without_dynamic_labels():
    before = worker_metrics.COMMITTED_FLOWS._value.get()
    worker_metrics.record_cycle(
        {"processed": 3, "retried": 0, "dead_lettered": 1}, .05
    )
    assert worker_metrics.COMMITTED_FLOWS._value.get() == before + 3
    assert not worker_metrics.COMMITTED_FLOWS._labelnames
