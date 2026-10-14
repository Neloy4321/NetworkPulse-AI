"""P0 DB migration, integrity, concurrency, and backup regression tests."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import create_engine, func, inspect, select, text

from networkpulse.detector import train
from networkpulse.migrations import _config, database_version, upgrade_database
from networkpulse.service import ingest
from networkpulse.simulator import sample_flows
from networkpulse.storage import Alert, NetworkEvent, build_sessions


def test_new_schema_and_64_bit_counters(tmp_path):
    url = "sqlite:///" + str(tmp_path / "new.db")
    assert upgrade_database(url)["revision"] == "0005_mlops_drift_runs"
    session_factory = build_sessions(url)
    model = train(sample_flows(140, seed=11), seed=11)
    large = sample_flows(100, seed=2)[0].model_copy(update={
        "orig_bytes": 9_000_000_000, "resp_bytes": 4_000_000_000,
        "orig_pkts": 3_000_000_000, "resp_pkts": 2_000_000_000,
    })
    with session_factory() as session:
        result = ingest(session, model, [large])
        assert result["inserted"] == 1
        stored = session.get(NetworkEvent, large.key())
        assert stored.orig_bytes == 9_000_000_000
        assert stored.resp_pkts == 2_000_000_000
    engine = session_factory.kw["bind"]
    assert "idx_flow_anomalous_time" in {i["name"] for i in inspect(engine).get_indexes("network_events")}
    assert "idx_alert_status_created" in {i["name"] for i in inspect(engine).get_indexes("alerts")}
    engine.dispose()


def test_legacy_database_upgrade_preserves_events_alerts(tmp_path):
    """Simulate v0.1 SQLite without Alembic version and with existing data."""
    path = tmp_path / "legacy.db"
    url = "sqlite:///" + str(path)
    eng = create_engine(url)
    with eng.begin() as c:
        command.upgrade(_config(c), "0001_legacy_baseline")
        c.execute(text("INSERT INTO network_events (id, timestamp, source, src_ip, dst_ip, "
                       "orig_bytes, resp_bytes, orig_pkts, resp_pkts) "
                       "VALUES ('legacy-event', '2026-01-01 10:00:00', 'zeek', '10.0.0.1', "
                       "'10.0.0.2', 10, 20, 2, 3)"))
        c.execute(text("INSERT INTO alerts (id, event_id, severity, status, reasons) "
                       "VALUES (11, 'legacy-event', 'high', 'open', '[]')"))
        c.execute(text("DROP TABLE alembic_version"))
    eng.dispose()
    result = upgrade_database(url)
    assert result["revision"] == "0005_mlops_drift_runs"
    assert result["sqlite_backup"] and Path(result["sqlite_backup"]).is_file()
    maker = build_sessions(url)
    with maker() as session:
        assert session.get(NetworkEvent, "legacy-event").orig_bytes == 10
        assert session.get(Alert, 11).event_id == "legacy-event"
        assert session.scalar(select(func.count(Alert.id))) == 1
    maker.kw["bind"].dispose()
    # SQLite pre-migration backup remains a valid independent copy.
    backup = create_engine("sqlite:///" + str(result["sqlite_backup"]))
    with backup.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM alerts")).scalar_one() == 1
        assert "alembic_version" not in inspect(conn).get_table_names()
    backup.dispose()


def test_unmigrated_database_refuses_start(tmp_path):
    url = "sqlite:///" + str(tmp_path / "notyet.db")
    with pytest.raises(RuntimeError, match="db upgrade"):
        build_sessions(url)
    assert database_version(url)["revision"] is None


def test_concurrent_duplicate_ingestion_is_atomic(tmp_path):
    url = "sqlite:///" + str(tmp_path / "concurrent.db")
    upgrade_database(url)
    maker = build_sessions(url)
    detector = train(sample_flows(140, seed=21), seed=21)
    flows = sample_flows(140, seed=21)[105:120]

    def worker():
        with maker() as session:
            return ingest(session, detector, flows)

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(lambda _: worker(), range(5)))
    assert sum(x["inserted"] for x in results) == len(flows)
    assert sum(x["alerts_created"] for x in results) <= len(flows)
    with maker() as session:
        assert session.scalar(select(func.count(NetworkEvent.id))) == len(flows)
        assert session.scalar(select(func.count(Alert.id))) == sum(x["alerts_created"] for x in results)
    maker.kw["bind"].dispose()


def test_repeated_upgrade_is_safe(tmp_path):
    url = "sqlite:///" + str(tmp_path / "new.db")
    assert upgrade_database(url)["revision"] == "0005_mlops_drift_runs"
    assert upgrade_database(url)["revision"] == "0005_mlops_drift_runs"


def test_backup_and_restore_preserves_alerts(tmp_path):
    from networkpulse.migrations import backup_sqlite

    path = tmp_path / "original.db"
    url = "sqlite:///" + str(path)
    upgrade_database(url)
    maker = build_sessions(url)
    detector = train(sample_flows(140, seed=14), seed=14)
    with maker() as session:
        ingest(session, detector, sample_flows(140, seed=14)[105:])
        expected = session.scalar(select(func.count(NetworkEvent.id)))
    maker.kw["bind"].dispose()

    backup = tmp_path / "snapshot.db"
    assert Path(backup_sqlite(url, backup)["backup"]).is_file()
    # Restoring by copying into an isolated destination must retain all events.
    restored = tmp_path / "restored.db"
    restored.write_bytes(backup.read_bytes())
    restored_maker = build_sessions("sqlite:///" + str(restored))
    with restored_maker() as session:
        assert session.scalar(select(func.count(NetworkEvent.id))) == expected
        assert session.scalar(select(func.count(Alert.id))) >= 1
    restored_maker.kw["bind"].dispose()
    with pytest.raises(ValueError, match="new and different"):
        backup_sqlite(url, backup)


def test_sqlite_foreign_keys_enforced(tmp_path):
    from sqlalchemy.exc import IntegrityError

    url = "sqlite:///" + str(tmp_path / "fk.db")
    upgrade_database(url)
    maker = build_sessions(url)
    with pytest.raises(IntegrityError):
        with maker() as session:
            with session.begin():
                session.add(Alert(event_id="absent-flow", severity="high", status="open"))
    maker.kw["bind"].dispose()
