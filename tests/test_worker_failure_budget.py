"""Worker stall supervisor regression: no retries may masquerade as readiness."""
import pytest

from networkpulse.streaming.redis_streams import process_events
from networkpulse.streaming.worker_recovery import (
    WorkerFailureBudget, WorkerStalledError,
)


def test_failure_budget_requires_a_committed_batch_to_reset():
    budget = WorkerFailureBudget(max_stall_seconds=30, max_backoff_seconds=2)
    assert not budget.degraded
    budget.record_handler_failure(100)
    assert budget.degraded and budget.failures == 1
    assert budget.retry_delay(100) == .25
    budget.record_handler_failure(101)
    assert budget.retry_delay(101) == .5
    budget.assert_not_expired(129.9)
    with pytest.raises(WorkerStalledError, match="stalled"):
        budget.assert_not_expired(130)
    budget.committed_batch()
    assert not budget.degraded and budget.failures == 0
    budget.assert_not_expired(1000)
    assert budget.retry_delay(1000) == 0


@pytest.mark.parametrize("timeout,backoff", [
    (0, 2), (901, 2), (60, 0), (60, 16),
])
def test_policy_rejects_invalid_operational_limits(timeout, backoff):
    with pytest.raises(ValueError):
        WorkerFailureBudget(max_stall_seconds=timeout, max_backoff_seconds=backoff)


def test_worker_fails_closed_after_sustained_handler_failure(app_settings, monkeypatch):
    from networkpulse.streaming import redis_streams

    class NeverCommitted:
        calls = 0

        def initialize(self):
            pass

        def consume_batch_once(self, *_args, on_handler_failure=None, **_kwargs):
            self.calls += 1
            if self.calls == 1:
                assert on_handler_failure is not None
                on_handler_failure()
                return {"processed": 0, "retried": 25, "dead_lettered": 0}
            return {"processed": 0, "retried": 0, "dead_lettered": 0}

    heartbeats = []
    monkeypatch.setattr("networkpulse.ops_health.mark_success",
                        lambda *args: heartbeats.append(args))
    # Process clocks/sleeps are injected; the system clock and CI services
    # remain untouched. Real Redis/Pg outage tests separately test pending.
    fake = [100.]
    sleeps = []

    def sleeper(seconds):
        sleeps.append(seconds)
        fake[0] += max(seconds, 3.5)

    queue = NeverCommitted()
    with pytest.raises(WorkerStalledError, match="stalled"):
        process_events(
            queue, "ci-sustained-failure", settings=app_settings,
            clock=lambda: fake[0], sleeper=sleeper,
            max_stall_seconds=30, retry_backoff_max_seconds=2,
        )
    assert queue.calls > 1
    assert sleeps and all(0 < x <= 2 for x in sleeps)
    assert not heartbeats, "Empty polls must never disguise a failed batch"


def test_successful_post_failure_commit_rearms_worker_health(app_settings, monkeypatch):
    calls = []
    monkeypatch.setattr("networkpulse.ops_health.mark_success",
                        lambda *args: calls.append(args))
    fake = [0.]
    class Queue:
        calls = 0
        def initialize(self):
            pass

        def consume_batch_once(self, *_args, on_handler_failure=None, **_kwargs):
            self.calls += 1
            if self.calls == 1:
                on_handler_failure()
                return {"processed": 0, "retried": 25, "dead_lettered": 0}
            if self.calls == 2:
                return {"processed": 0, "retried": 0, "dead_lettered": 0}
            if self.calls == 3:
                # A successful processed result means Redis verified a committed
                # transaction before ACK; this fake exercises supervisor wiring.
                return {"processed": 25, "retried": 0, "dead_lettered": 0}
            raise RuntimeError("stop test worker after checking progress")

    def sleeper(seconds):
        fake[0] += seconds

    queue = Queue()
    with pytest.raises(RuntimeError, match="stop test worker"):
        process_events(
            queue, "ci-recovered", settings=app_settings,
            clock=lambda: fake[0], sleeper=sleeper,
            max_stall_seconds=30, retry_backoff_max_seconds=2,
        )
    assert queue.calls == 4
    # Neither failed processing nor empty polls refreshed liveness; a
    # successful batch and the following DB-probed idle cycle did.
    assert len(calls) == 2
