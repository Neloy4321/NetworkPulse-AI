"""Fail-closed retry budget for a persistently failing Redis flow worker.

Transport retains valid messages in Redis pending until DB commit. This policy
does not retry or acknowledge messages itself: it controls worker health and
bounded retries after native model/transaction failures.

The budget spans empty polls so an idle Redis response cannot erase a prior
failed transaction. A successful committed batch is the ONLY reset.
"""
from __future__ import annotations

from dataclasses import dataclass


class WorkerStalledError(RuntimeError):
    """No committed progress after a handler failure within the allowed window."""


@dataclass
class WorkerFailureBudget:
    max_stall_seconds: float = 90.0
    max_backoff_seconds: float = 4.0
    first_failure_at: float | None = None
    failures: int = 0

    def __post_init__(self) -> None:
        if not 30 <= self.max_stall_seconds <= 900:
            raise ValueError("Worker stall budget must be between 30 and 900 seconds")
        if not 0.05 <= self.max_backoff_seconds <= 15:
            raise ValueError("Worker retry backoff cap must be between 0.05 and 15 seconds")

    @property
    def degraded(self) -> bool:
        return self.first_failure_at is not None

    def record_handler_failure(self, now: float) -> None:
        if self.first_failure_at is None:
            self.first_failure_at = now
        self.failures += 1
        self.assert_not_expired(now)

    def assert_not_expired(self, now: float) -> None:
        if self.first_failure_at is not None and now - self.first_failure_at >= self.max_stall_seconds:
            raise WorkerStalledError(
                "Stream worker stalled without a successful database commit; "
                "leaving Redis deliveries pending for supervised restart"
            )

    def committed_batch(self) -> None:
        self.first_failure_at = None
        self.failures = 0

    def retry_delay(self, now: float) -> float:
        """Bounded exponential backoff, clipped by the remaining health budget."""
        self.assert_not_expired(now)
        if self.first_failure_at is None:
            return 0.0
        exponent = min(self.failures - 1, 6)
        base = min(self.max_backoff_seconds, 0.25 * (2 ** max(0, exponent)))
        remaining = max(0.0, self.max_stall_seconds - (now - self.first_failure_at))
        return min(base, remaining)
