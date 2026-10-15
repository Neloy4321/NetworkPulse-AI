"""Operator staging load safety, evidence integrity and real-service recovery."""
import hashlib
import json
import os
import stat
import uuid

import pytest

from networkpulse.simulator import sample_flows
from networkpulse.staging_load import (
    StagingPlan, authorize_staging_target, load_source, percentile,
    run_staging_load, write_report,
)


@pytest.mark.parametrize("kwargs", [
    {"duration_seconds": 0}, {"duration_seconds": 3601},
    {"rate": 0}, {"rate": 501}, {"max_events": 99},
    {"rate": 500, "duration_seconds": 3600},
    {"drain_timeout_seconds": 9}, {"max_p99_queue_seconds": 0},
    {"min_verified_throughput": 0},
])
def test_staging_load_refuses_unbounded_or_invalid_configuration(kwargs):
    with pytest.raises(ValueError):
        StagingPlan(**kwargs)


def test_percentiles_are_nearest_rank_not_averaged():
    assert percentile([.1, .2, .3, 1, 9], .5) == .3
    assert percentile([.1, .2, .3, 1, 9], .95) == 9
    with pytest.raises(ValueError, match="No successful"):
        percentile([], .99)


def test_source_hash_and_duplicate_and_corpus_length_gates(tmp_path):
    flows = [
        e.model_copy(update={"source": "canonical"})
        for e in sample_flows(110, seed=6021)[:12]
    ]
    path = tmp_path / "approved.jsonl"
    source = "".join(json.dumps(f.model_dump(mode="json")) + "\n" for f in flows)
    path.write_text(source)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    loaded, observed = load_source(path, "canonical", digest, 10)
    assert observed == digest and len(loaded) == 10
    assert all(e.source == "canonical" for e in loaded)
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        load_source(path, "canonical", "0" * 64, 10)
    with pytest.raises(ValueError, match="Insufficient"):
        load_source(path, "canonical", digest, 20)
    path.write_text(source + json.dumps(flows[0].model_dump(mode="json")) + "\n")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="duplicate canonical IDs"):
        load_source(path, "canonical", digest, 20)


def test_source_rejects_simulated_traffic_claimed_as_real(tmp_path):
    f = sample_flows(100, seed=6022)[0]
    path = tmp_path / "not-real.jsonl"
    path.write_text(json.dumps(f.model_dump(mode="json")) + "\n")
    with pytest.raises(ValueError, match="Synthetic simulator"):
        load_source(path, "canonical", hashlib.sha256(path.read_bytes()).hexdigest(), 1)


def test_evidence_file_is_owner_only_and_immutable(tmp_path):
    report = tmp_path / "evidence" / "run.json"
    write_report(report, {"status": "passed", "run_id": "first"})
    assert stat.S_IMODE(report.stat().st_mode) == 0o600
    assert json.loads(report.read_text())["run_id"] == "first"
    with pytest.raises(FileExistsError):
        write_report(report, {"status": "failed"})
    assert json.loads(report.read_text())["status"] == "passed"


def test_unauthorized_target_rejected_before_io():
    class MustNotConnect:
        def __call__(self):
            raise AssertionError("No database calls allowed")
    with pytest.raises(ValueError, match="Explicit isolated"):
        authorize_staging_target(
            maker=MustNotConnect(), redis_client=object(),
            expected_database="networkpulse", confirmed=False,
        )


@pytest.mark.skipif(
    not (os.getenv("REDIS_TEST_URL") and os.getenv("PG_TEST_DATABASE_URL")),
    reason="Real Redis 7 and PostgreSQL 16 integration services required",
)
def test_real_staging_sustained_load_and_precommit_recovery():
    """Ten-second service integration uses synthetic CI fixture, NOT field evidence."""
    import redis
    from networkpulse.detector import train
    from networkpulse.migrations import upgrade_database
    from networkpulse.storage import build_sessions

    db_url = os.environ["PG_TEST_DATABASE_URL"]
    upgrade_database(db_url)
    maker = build_sessions(db_url)
    client = redis.Redis.from_url(os.environ["REDIS_TEST_URL"], decode_responses=True)
    try:
        authorize_staging_target(
            maker=maker, redis_client=client,
            expected_database="networkpulse_ci", confirmed=True,
        )
        model = train(sample_flows(320, seed=6030), seed=6030)
        flows = [
            e.model_copy(update={"source": "canonical"})
            for e in sample_flows(120, seed=6031)[:10]
        ]
        plan = StagingPlan(
            rate=1, duration_seconds=10, max_events=100,
            drain_timeout_seconds=30,
            max_p99_queue_seconds=60, min_verified_throughput=.1,
        )
        report = run_staging_load(
            events=flows, client=client, maker=maker, model=model, plan=plan,
            run_id=uuid.uuid4().hex,
        )
        assert report["status"] == "passed"
        assert report["published"] == 10
        assert report["persisted_unique_event_ids"] == 10
        assert report["new_sql_rows_inserted"] == 10
        assert report["acknowledged_after_commit"] == 10
        assert report["pending"] == report["dead_letters"] == 0
        assert report["injected_failure_batches"] == 1
        assert report["recovered_consumer_switches"] == 1
        assert report["queue_to_ack_seconds"]["p99"] >= 0
        assert report["measured_elapsed_seconds"] >= 9
    finally:
        maker.kw["bind"].dispose()
        client.close()


@pytest.mark.skipif(
    not (os.getenv("REDIS_TEST_URL") and os.getenv("PG_TEST_DATABASE_URL")),
    reason="Real isolated staging services required",
)
def test_guard_rejects_wrong_database_and_default_redis_db():
    import redis
    from networkpulse.migrations import upgrade_database
    from networkpulse.storage import build_sessions

    url = os.environ["PG_TEST_DATABASE_URL"]
    upgrade_database(url)
    maker = build_sessions(url)
    client = redis.Redis.from_url(os.environ["REDIS_TEST_URL"], decode_responses=True)
    try:
        with pytest.raises(ValueError, match="differs"):
            authorize_staging_target(
                maker=maker, redis_client=client,
                expected_database="notreal_staging", confirmed=True,
            )
        with pytest.raises(ValueError, match="isolated database"):
            bad_client = redis.Redis.from_url(
                os.environ["REDIS_TEST_URL"].rsplit("/", 1)[0] + "/0",
                decode_responses=True,
            )
            try:
                authorize_staging_target(
                    maker=maker, redis_client=bad_client,
                    expected_database="networkpulse_ci", confirmed=True,
                )
            finally:
                bad_client.close()
    finally:
        maker.kw["bind"].dispose()
        client.close()


def test_monotonic_producer_pacing_never_uses_negative_sleep():
    from networkpulse.staging_load import wait_until

    # A time jump across the scheduling deadline must cause termination,
    # rather than re-reading the clock and attempting sleep(-epsilon).
    readings = iter([10.99, 11.0001])
    calls = []
    wait_until(11.0, clock=lambda: next(readings), sleeper=calls.append)
    assert len(calls) == 1
    assert calls[0] == pytest.approx(.01)
    assert all(value > 0 for value in calls)

    wait_until(10.0, clock=lambda: 10.0001,
               sleeper=lambda _: pytest.fail("Should already be due"))
