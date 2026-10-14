"""Run only when an isolated PostgreSQL test database is supplied (CI service)."""

import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import BigInteger, func, inspect, select

from networkpulse.behavior import activity_windows
from networkpulse.detector import train
from networkpulse.migrations import upgrade_database
from networkpulse.service import ingest
from networkpulse.simulator import sample_flows
from networkpulse.storage import Alert, NetworkEvent, build_sessions


@pytest.mark.skipif(not os.getenv("PG_TEST_DATABASE_URL"), reason="No CI PostgreSQL service")
def test_postgres_migration_bigint_and_upsert_contention():
    url = os.environ["PG_TEST_DATABASE_URL"]
    assert upgrade_database(url)["revision"] == "0005_mlops_drift_runs"
    maker = build_sessions(url)
    engine = maker.kw["bind"]
    try:
        counter_names = ("orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts")
        cols = {c["name"]: c["type"] for c in inspect(engine).get_columns("network_events")}
        assert all(isinstance(cols[name], BigInteger) for name in counter_names)

        samples = sample_flows(145, seed=27)
        detector = train(samples, seed=27)
        flows = samples[110:130]
        flows[0] = flows[0].model_copy(update={"orig_bytes": 9_000_000_000})

        def worker():
            with maker() as session:
                return ingest(session, detector, flows)

        with ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(lambda _: worker(), range(5)))
        assert sum(x["inserted"] for x in results) == len(flows)
        with maker() as session:
            assert session.scalar(select(func.count(NetworkEvent.id))) == len(flows)
            assert session.scalar(select(func.count(Alert.id))) == sum(x["alerts_created"] for x in results)
            assert session.get(NetworkEvent, flows[0].key()).orig_bytes == 9_000_000_000
            # This runs the new production SQL window aggregation against the
            # real PostgreSQL CI service, using the rows ingested above.
            behavior = activity_windows(
                session, until=max(e.timestamp for e in flows),
                lookback_minutes=1440, window_minutes=5, limit=100,
            )
            assert sum(w["flow_count"] for w in behavior["windows"]) == len(flows)
            assert all(w["distinct_destination_hosts"] >= 1 for w in behavior["windows"])
    finally:
        engine.dispose()


@pytest.mark.skipif(not os.getenv("PG_TEST_DATABASE_URL"), reason="No CI PostgreSQL service")
def test_postgres_concurrent_behavior_case_upserts_preserve_unique_incident():
    """Concurrent worker overlap cannot create duplicate source/window cases."""
    from datetime import datetime, timezone
    from networkpulse.behavior_cases import finding_id, materialize_findings
    from networkpulse.schemas import FlowEvent
    from networkpulse.storage import BehaviorFinding

    url = os.environ["PG_TEST_DATABASE_URL"]
    upgrade_database(url)
    maker = build_sessions(url)
    seed = sample_flows(310, seed=19)
    detector = train(seed, seed=19)
    template = seed[0].model_dump(mode="json")
    events = []
    for i in range(8):
        value = dict(template)
        value.update({
            "timestamp": datetime(2026, 10, 14, 12, 1, i,
                                  tzinfo=timezone.utc).isoformat(),
            "source": "canonical", "src_ip": "198.51.100.218",
            "dst_ip": f"203.0.113.{10 + i % 4}", "dst_port": 9000 + i,
        })
        events.append(FlowEvent.model_validate(value))
    boundary = datetime(2026, 10, 14, 12, 5, tzinfo=timezone.utc)

    try:
        with maker() as db:
            assert ingest(db, detector, events)["inserted"] == len(events)

        def run_worker(_):
            with maker() as db:
                return materialize_findings(
                    db, until=boundary, lateness_minutes=0, lookback_minutes=5,
                    min_ports=2, min_destinations=2,
                )

        with ThreadPoolExecutor(max_workers=3) as executor:
            reports = list(executor.map(run_worker, range(3)))
        assert all(r["candidate_upserts"] >= 1 for r in reports)
        with maker() as db:
            key = finding_id("198.51.100.218", datetime(
                2026, 10, 14, 12, 0, tzinfo=timezone.utc,
            ))
            stored = db.get(BehaviorFinding, key)
            assert stored is not None and stored.flow_count == len(events)
            assert db.scalar(select(func.count(BehaviorFinding.id)).where(
                BehaviorFinding.source_ip == "198.51.100.218",
            )) == 1
    finally:
        maker.kw["bind"].dispose()


@pytest.mark.skipif(not os.getenv("PG_TEST_DATABASE_URL"), reason="No CI PostgreSQL service")
def test_postgres_concurrent_mlops_snapshot_upsert():
    """Two monitoring workers must emit one exact immutable report."""
    from datetime import datetime, timedelta, timezone
    from networkpulse.mlops_monitor import run_monitor
    from networkpulse.model_registry import sha256
    from networkpulse.storage import MLOpsDriftRun
    from pathlib import Path
    import tempfile

    url = os.environ["PG_TEST_DATABASE_URL"]
    upgrade_database(url)
    samples = sample_flows(310, seed=47)
    detector = train(samples, seed=47)
    selected = samples[230:310]
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "trusted.joblib"
        detector.save(path)
        expected = sha256(path)
        maker = build_sessions(url)
        try:
            with maker() as db:
                assert ingest(db, detector, selected)["inserted"] == len(selected)
            start = selected[0].timestamp - timedelta(seconds=1)
            end = selected[-1].timestamp + timedelta(minutes=5)

            def monitor(_):
                with maker() as db:
                    return run_monitor(db, model_path=path, expected_sha256=expected,
                                       start=start, end=end)

            with ThreadPoolExecutor(max_workers=3) as executor:
                reports = list(executor.map(monitor, range(3)))
            assert len({r["id"] for r in reports}) == 1
            assert sum(bool(r["created"]) for r in reports) == 1
            with maker() as db:
                assert db.scalar(select(func.count(MLOpsDriftRun.id)).where(
                    MLOpsDriftRun.model_sha256 == expected,
                )) == 1
        finally:
            maker.kw["bind"].dispose()
