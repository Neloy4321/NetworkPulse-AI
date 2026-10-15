"""Safety-gated sustained Redis -> native detector -> PostgreSQL staging validation.

This is operational acceptance tooling. It never touches default Redis queue
names or mutates an existing flow, and cannot certify live-site failover.
A single injected handler failure exercises unacked delivery recovery while
the producer continues replaying *unchanged* approved source flow metadata.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Lock

from sqlalchemy import select, text

from networkpulse.adapters import iter_jsonl
from networkpulse.schemas import FlowEvent
from networkpulse.service import ingest
from networkpulse.storage import NetworkEvent
from networkpulse.streaming.redis_streams import BackpressureError, FlowStream


@dataclass(frozen=True)
class StagingPlan:
    rate: int = 20
    duration_seconds: int = 60
    drain_timeout_seconds: int = 120
    max_events: int = 25000
    max_p99_queue_seconds: float = 120.0
    min_verified_throughput: float = 1.0

    def __post_init__(self):
        if not 1 <= self.rate <= 500 or not 10 <= self.duration_seconds <= 3600:
            raise ValueError("Rate must be 1..500/s and duration 10..3600s")
        if not 10 <= self.drain_timeout_seconds <= 900:
            raise ValueError("Drain timeout must be 10..900 seconds")
        if not 100 <= self.max_events <= 50000:
            raise ValueError("Maximum event count must be 100..50000")
        if self.target_count > self.max_events:
            raise ValueError("Requested sustained rate/duration exceeds bounded event cap")
        if not 0 < self.max_p99_queue_seconds <= 3600:
            raise ValueError("p99 acceptance threshold must be 0..3600 seconds")
        if not 0 < self.min_verified_throughput <= self.rate * 2:
            raise ValueError("Minimum measured throughput must be positive and plausible")

    @property
    def target_count(self) -> int:
        return self.rate * self.duration_seconds


def authorize_staging_target(*, maker, redis_client, expected_database: str,
                             confirmed: bool) -> None:
    """Refuse production/default resources BEFORE creating any stream or rows."""
    if not confirmed or not expected_database.endswith(("_staging", "_ci")):
        raise ValueError("Explicit isolated staging confirmation and *_staging/*_ci DB required")
    with maker() as session:
        if session.get_bind().dialect.name != "postgresql":
            raise ValueError("Staging validation requires real PostgreSQL")
        found = session.execute(text("SELECT current_database()")).scalar_one()
        if found != expected_database:
            raise ValueError("Current PostgreSQL database differs from approved staging target")
    # Require an explicitly isolated Redis logical database, not app default /0.
    db_index = int(redis_client.connection_pool.connection_kwargs.get("db", 0))
    if not 1 <= db_index <= 15:
        raise ValueError("Staging Redis must use isolated database 1..15, never /0")
    redis_client.ping()


def load_source(path: Path, fmt: str, expected_sha256: str, count: int
                ) -> tuple[list[FlowEvent], str]:
    """Pin source bytes, reject ambiguous replay keys and insufficient capture."""
    if len(expected_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in expected_sha256):
        raise ValueError("Expected source SHA256 must be 64 lowercase hex characters")
    source_hash = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            source_hash.update(chunk)
    digest = source_hash.hexdigest()
    if digest != expected_sha256:
        raise ValueError("Approved source SHA256 mismatch")
    events = []
    keys = set()
    for event in iter_jsonl(path, fmt):
        if event.source == "simulator":
            raise ValueError("Synthetic simulator traffic prohibited for staging evidence")
        key = event.key()
        if key in keys:
            raise ValueError("Source has duplicate canonical IDs, unsafe for exact reconciliation")
        keys.add(key)
        events.append(event)
        if len(events) == count:
            break
    if len(events) != count:
        raise ValueError("Insufficient distinct real source events for sustained workload")
    # Reject a source modified after the initial integrity check.
    source_hash_2 = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            source_hash_2.update(chunk)
    if source_hash_2.hexdigest() != digest:
        raise ValueError("Source changed during staging preflight")
    return events, digest


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        raise ValueError("No successful completion samples")
    ordered = sorted(values)
    rank = max(0, math.ceil(fraction * len(ordered)) - 1)
    return round(ordered[rank], 6)


def _verify_absent(maker, keys: list[str]) -> None:
    with maker() as session:
        for start in range(0, len(keys), 250):
            present = session.scalars(
                select(NetworkEvent.id).where(NetworkEvent.id.in_(keys[start:start + 250]))
            ).first()
            if present is not None:
                raise ValueError("Existing staging event ID: use fresh isolated capture/database")


def _verify_exact(maker, keys: list[str]) -> int:
    seen: set[str] = set()
    with maker() as session:
        for start in range(0, len(keys), 250):
            seen.update(session.scalars(
                select(NetworkEvent.id).where(NetworkEvent.id.in_(keys[start:start + 250]))
            ).all())
    if seen != set(keys):
        raise RuntimeError("Staging SQL event-ID reconciliation failed; preserve queue for triage")
    return len(seen)


def run_staging_load(*, events: list[FlowEvent], client, maker, model,
                     plan: StagingPlan, run_id: str | None = None) -> dict:
    """Paced producer and concurrent real SQL/Redis worker, bounded recovery.

    An injected one-time handler fault occurs strictly before the DB commit.
    This simulates a crashed scoring handler, NOT network-level Redis or
    PostgreSQL node failover. Queue is left intact on failure for forensics.
    """
    if len(events) != plan.target_count:
        raise ValueError("Workload must contain exactly the authorized number of flows")
    keys = [event.key() for event in events]
    if len(set(keys)) != len(keys):
        raise ValueError("Workload contains duplicate canonical IDs")
    _verify_absent(maker, keys)
    run_id = uuid.uuid4().hex if run_id is None else run_id
    if len(run_id) != 32 or any(ch not in "0123456789abcdef" for ch in run_id):
        raise ValueError("Staging run identifier must be exactly 32 lowercase hex characters")
    stream = "networkpulse:staging:" + run_id
    queue = FlowStream(
        client, stream=stream, group="staging-validation",
        max_backlog=min(50000, max(100, plan.rate * 5)),
    )
    queue.initialize()
    done = Event()
    shared_lock = Lock()
    queue_latencies: list[float] = []
    batch_latencies: list[float] = []
    failure_count = 0
    recoveries = 0
    ack_count = 0
    inserted_rows = 0
    max_queue_depth = 0
    start = time.monotonic()
    deadline = start + plan.duration_seconds + plan.drain_timeout_seconds

    def worker():
        nonlocal failure_count, recoveries, ack_count, inserted_rows
        consumer = "staging-before-failure:" + run_id
        inject = True
        while not done.is_set() or client.xlen(stream) > 0:
            if time.monotonic() > deadline:
                raise TimeoutError("Staging drain deadline exceeded")
            def transaction(batch):
                nonlocal inject, inserted_rows
                if inject:
                    inject = False
                    raise ConnectionError("One-time controlled pre-commit fault")
                with maker() as session:
                    receipt = ingest(session, model, batch)
                with shared_lock:
                    inserted_rows += receipt["inserted"]

            def record_ack(ids):
                nonlocal ack_count
                seconds, micros = client.time()
                server_ms = int(seconds) * 1000 + int(micros) // 1000
                measurements = [
                    max(0.0, (server_ms - int(msg_id.split("-", 1)[0])) / 1000)
                    for msg_id in ids
                ]
                with shared_lock:
                    queue_latencies.extend(measurements)
                    ack_count += len(ids)

            step_started = time.monotonic()
            outcome = queue.consume_batch_once(
                consumer, transaction, FlowEvent.model_validate,
                recover=True, recover_idle_ms=0, block_ms=50,
                on_committed=record_ack,
            )
            if any(outcome.values()):
                with shared_lock:
                    batch_latencies.append(time.monotonic() - step_started)
            if outcome["dead_lettered"]:
                raise RuntimeError("Staging found poison deliveries; preserve DLQ for triage")
            if outcome["retried"]:
                failure_count += 1
                if failure_count != 1:
                    raise RuntimeError("Unexpected additional handler failures")
                if client.xpending(stream, queue.group)["pending"] == 0:
                    raise RuntimeError("Injected handler failure lost pending Redis records")
                consumer = "staging-recovered:" + run_id
                recoveries += 1

    try:
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="staging-worker") as pool:
            future = pool.submit(worker)
            try:
                for index, event in enumerate(events):
                    if future.done():
                        future.result()
                        raise RuntimeError("Worker stopped before publisher completed")
                    schedule = start + index / plan.rate
                    # Read the monotonic clock only once per iteration:
                    # a second read can cross the deadline and otherwise
                    # pass a negative duration into sleep() under load.
                    while True:
                        remaining = schedule - time.monotonic()
                        if remaining <= 0:
                            break
                        time.sleep(min(0.01, remaining))
                    while True:
                        if time.monotonic() > deadline:
                            raise TimeoutError("Staging publisher exceeded deadline")
                        if future.done():
                            future.result()
                            raise RuntimeError("Staging worker terminated early")
                        try:
                            queue.enqueue(event.model_dump(mode="json"))
                            break
                        except BackpressureError:
                            time.sleep(0.02)
                    if index % 25 == 0:
                        max_queue_depth = max(max_queue_depth, int(client.xlen(stream)))
            finally:
                done.set()
            future.result(timeout=plan.drain_timeout_seconds + 5)
        elapsed = time.monotonic() - start
        if failure_count != 1 or recoveries != 1:
            raise RuntimeError("Injected handler-failure recovery was not observed")
        if ack_count != len(events) or len(queue_latencies) != len(events):
            raise RuntimeError("ACK reconciliation failed; preserve Redis state for triage")
        if inserted_rows != len(events):
            raise RuntimeError("Staging contained preexisting or concurrent event IDs")
        if client.xlen(stream) != 0:
            raise RuntimeError("Live Redis stream was not completely drained")
        if client.xpending(stream, queue.group)["pending"] != 0:
            raise RuntimeError("Unacknowledged Redis pending messages remain")
        if client.xlen(queue.dead_letter) != 0:
            raise RuntimeError("Staging DLQ is not empty; manual triage required")
        verified = _verify_exact(maker, keys)
        throughput = round(verified / max(elapsed, .000001), 3)
        p99 = percentile(queue_latencies, .99)
        return {
            "schema_version": 1,
            "scope": "isolated_staging_real_redis_postgresql",
            "run_id": run_id, "stream": stream, "status": (
                "passed" if p99 <= plan.max_p99_queue_seconds
                and throughput >= plan.min_verified_throughput else "slo_failed"
            ),
            "producer_rate_target_per_second": plan.rate,
            "scheduled_seconds": plan.duration_seconds,
            "measured_elapsed_seconds": round(elapsed, 3),
            "published": len(events), "acknowledged_after_commit": ack_count,
            "persisted_unique_event_ids": verified,
            "new_sql_rows_inserted": inserted_rows, "pending": 0, "dead_letters": 0,
            "fault_injection": "one_precommit_handler_exception_not_node_failover",
            "injected_failure_batches": failure_count, "recovered_consumer_switches": recoveries,
            "peak_sampled_queue_depth": max_queue_depth,
            "verified_flows_per_second": throughput,
            "queue_to_ack_seconds": {
                "p50": percentile(queue_latencies, .5),
                "p95": percentile(queue_latencies, .95), "p99": p99,
            },
            "active_batch_cycle_seconds": {
                "p50": percentile(batch_latencies, .5),
                "p95": percentile(batch_latencies, .95),
                "p99": percentile(batch_latencies, .99),
            },
            "acceptance": {
                "max_p99_queue_seconds": plan.max_p99_queue_seconds,
                "min_verified_throughput": plan.min_verified_throughput,
            },
            "limitations": [
                "Not packet-to-alert latency or independent site SLO certification",
                "Fault injection is a handler exception, not real DB/Redis host failover",
                "Report requires separate CPU, memory, offsite and failover evidence",
            ],
        }
    finally:
        # Never delete a failed run's queue or DLQ. Operators inspect state.
        pass


def write_report(path: Path, report: dict) -> None:
    """Write operator evidence atomically without world-readable privileges."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, candidate = tempfile.mkstemp(prefix=".staging-evidence-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        # Hard-link creation fails atomically when evidence already exists.
        # An operator cannot silently overwrite/erase a prior accepted run.
        os.link(candidate, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(candidate):
            os.unlink(candidate)
