"""Non-ML Stage B negative-path tests; live cases require dedicated CI PG/Redis."""
from __future__ import annotations

import os
import uuid

import pytest

from networkpulse.infra_event_harness import (
    CONFIRM, KIND, LabSettings, SyntheticIntegrityHarness, _percentile,
)
from networkpulse.infra_staging import DATABASE_NAME, STAGING_MODE


def test_refuses_nonisolated_or_unconfirmed_environments(monkeypatch):
    monkeypatch.delenv("NETWORKPULSE_STAGING_MODE", raising=False)
    with pytest.raises(ValueError, match="isolated"):
        LabSettings.from_env()
    monkeypatch.setenv("NETWORKPULSE_STAGING_MODE", STAGING_MODE)
    monkeypatch.delenv("NETWORKPULSE_STAGE_B_CONFIRM", raising=False)
    with pytest.raises(ValueError, match="consent"):
        LabSettings.from_env()
    monkeypatch.setenv("NETWORKPULSE_STAGE_B_CONFIRM", CONFIRM)
    monkeypatch.setenv("NETWORKPULSE_STAGING_DB_NAME", "networkpulse_ci")
    with pytest.raises(ValueError, match="non-staging"):
        LabSettings.from_env()
    monkeypatch.setenv("NETWORKPULSE_STAGING_DB_NAME", DATABASE_NAME)
    monkeypatch.setenv("NETWORKPULSE_STAGING_DB_PASSWORD", "changeme" + "x" * 25)
    with pytest.raises(ValueError, match="dedicated"):
        LabSettings.from_env()


def test_percentile_requires_real_samples():
    assert _percentile([], 95) is None
    assert _percentile([5.123456], 99) == 5.123
    assert _percentile([1, 2, 3, 4, 100], 95) == 100


@pytest.fixture
def staging_lab():
    if os.getenv("NETWORKPULSE_STAGE_B_REAL_CI") != "1":
        pytest.skip("Dedicated Stage B real database/Redis CI only")
    settings = LabSettings.from_env()
    pg, cache = settings.connect()
    harness = SyntheticIntegrityHarness(
        pg, cache, run_id=uuid.uuid4().hex, max_backlog=100,
    )
    try:
        harness.initialize_table()
        yield harness
    finally:
        harness.cleanup_synthetic_run()
        pg.close()
        cache.close()


def test_real_synthetic_backpressure_reconciliation_and_latency(staging_lab):
    h = staging_lab
    report = h.run(250)
    assert report["reconciled"] is True
    assert report["accepted_unique"] == 250
    assert report["db_unique"] == 250
    assert report["db_inserted_this_process"] == 250
    assert report["acknowledged_deliveries"] == 250
    assert report["redis_stream_depth"] == report["redis_pending"] == 0
    assert report["backpressure_events"] >= 1
    assert report["duplicate_effects_prevented"] == 0
    assert report["latency_sample_count"] == 250
    assert report["end_to_end_p99_ms"] >= report["end_to_end_p95_ms"] >= 0
    assert report["scope"] == "ISOLATED_CI_OR_AUTHORIZED_STAGING_NON_ML_ONLY"
    assert report["operational_acceptance"] == "NOT_CLAIMED"


def test_commit_then_redis_ack_failure_replay_prevents_duplicate_db_effects(
    staging_lab, monkeypatch,
):
    h = staging_lab
    h.enqueue(0)
    original = h.queue._ack_many

    def failed_ack(_ids):
        raise ConnectionError("CI simulated Redis ACK link failure")

    monkeypatch.setattr(h.queue, "_ack_many", failed_ack)
    with pytest.raises(ConnectionError, match="ACK"):
        h.process_once()
    assert h.cache.xpending(h.stream, h.queue.group)["pending"] == 1
    with h.pg.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM np_stage_b_synthetic_receipts WHERE run_id=%s",
            (h.run_id,),
        )
        assert cursor.fetchone()[0] == 1

    monkeypatch.setattr(h.queue, "_ack_many", original)
    assert h.drain() == 1
    report = h.reconcile()
    assert report["reconciled"] is True
    assert report["accepted_unique"] == report["db_unique"] == 1
    assert report["db_inserted_this_process"] == 1
    assert report["duplicate_effects_prevented"] == 1
    assert report["redis_pending"] == 0


def test_postgres_failure_keeps_delivery_pending_for_worker_recovery(
    staging_lab, monkeypatch,
):
    h = staging_lab
    h.enqueue(0)
    original = h._persist

    def unavailable(_batch):
        raise ConnectionError("CI simulated PostgreSQL transaction outage")

    monkeypatch.setattr(h, "_persist", unavailable)
    with pytest.raises(RuntimeError, match="pending failed"):
        h.process_once()
    assert h.cache.xlen(h.stream) == 1
    assert h.cache.xpending(h.stream, h.queue.group)["pending"] == 1
    assert h.inserted == 0
    monkeypatch.setattr(h, "_persist", original)
    assert h.drain() == 1
    assert h.reconcile()["reconciled"]
    assert h.duplicate_effects_prevented == 0


def test_invalid_synthetic_payload_cannot_be_written_or_acknowledged(staging_lab):
    h = staging_lab
    assert KIND.startswith("networkpulse-stage-b")
    h.queue.enqueue({
        "kind": KIND, "run_id": "foreign-lab", "event_id": "spoof", "ordinal": 0,
    })
    # Invalid synthetic payload remains pending: never mistake it for valid
    # processing or silently claim integrity PASS.
    with pytest.raises(RuntimeError, match="pending failed deliveries"):
        h.drain()
    assert h.cache.xpending(h.stream, h.queue.group)["pending"] == 1
    assert not h.reconcile()["reconciled"]
