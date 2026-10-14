"""Executable verified backup -> isolated restore -> audit-integrity regression drills.

Every test uses real DB storage, native SQLite backup or PostgreSQL pg_dump
and pg_restore. Never connect a drill to an actual production database.
"""
import json
import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from networkpulse.cli import main
from networkpulse.migrations import upgrade_database
from networkpulse.recovery import (
    create_snapshot, recovery_drill, verify_snapshot,
)
from networkpulse.storage import (
    Alert, AlertAudit, BehaviorFinding, BehaviorFindingAudit,
    BehaviorIncident, BehaviorIncidentAudit, MLOpsDriftRun, NetworkEvent,
    build_sessions,
)


def _seed_audited_rows(url: str) -> None:
    """One linked alert, finding, incident and drift report, no fake threat claim."""
    maker = build_sessions(url)
    timestamp = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)
    try:
        with maker() as db:
            if db.get(NetworkEvent, "recovery-ci-flow") is not None:
                return
            db.add(NetworkEvent(
                id="recovery-ci-flow", timestamp=timestamp, source="canonical",
                src_ip="198.51.100.10", dst_ip="203.0.113.20",
                src_port=53000, dst_port=443, proto="tcp", duration=2.0,
                orig_bytes=9_000_000_000, resp_bytes=16, orig_pkts=4,
                resp_pkts=2, conn_state="sf", anomaly_score=0.2,
                risk=30, anomalous=True,
            ))
            db.flush()
            alert = Alert(
                event_id="recovery-ci-flow", severity="medium",
                status="investigating", assigned_to="security-oncall",
                reasons=["review_required"],
            )
            db.add(alert)
            db.flush()
            db.add(AlertAudit(
                alert_id=alert.id, old_status="open", new_status="investigating",
                note="Investigated during recovery drill fixture",
                actor="ci-analyst",
            ))
            db.add(BehaviorFinding(
                id="a" * 32, source_ip="198.51.100.10",
                window_start=timestamp, window_minutes=5,
                patterns=["port_sweep_like"], flow_count=16, destination_ports=12,
                destination_hosts=2, flagged_flows=1, severity="medium",
                status="resolved", assigned_to="oncall",
            ))
            db.flush()
            db.add(BehaviorFindingAudit(
                finding_id="a" * 32, actor="ci-analyst",
                old_status="investigating", new_status="resolved",
                old_assignee=None, new_assignee="oncall",
                note="Reviewed original observation window",
            ))
            db.add(BehaviorIncident(
                id="b" * 32, source_ip="198.51.100.10",
                hour_start=timestamp, window_count=2,
                finding_ids=["a" * 32], patterns=["port_sweep_like"],
                first_seen=timestamp, last_seen=timestamp,
                total_flows=18, flagged_flows=1,
                severity="medium", status="resolved", assigned_to="oncall",
            ))
            db.flush()
            db.add(BehaviorIncidentAudit(
                incident_id="b" * 32, actor="ci-analyst",
                old_status="investigating", new_status="resolved",
                old_assignee=None, new_assignee="oncall",
                note="Reviewed correlated incident window",
            ))
            db.add(MLOpsDriftRun(
                id="c" * 32, model_sha256="d" * 64, window_start=timestamp,
                window_end=timestamp.replace(hour=13),
                input_fingerprint="e" * 64, flow_count=40,
                flagged_flows=2, drift_status="ok",
                alert_budget_exceeded=False, worst_psi=0.06,
                report={"source": "bounded-ci-drill", "labels_available": False},
            ))
            db.commit()
    finally:
        maker.kw["bind"].dispose()


def test_sqlite_snapshot_integrity_and_isolated_audit_restore(tmp_path, monkeypatch, capsys):
    url = "sqlite:///" + str(tmp_path / "production-like.db")
    upgrade_database(url)
    _seed_audited_rows(url)
    snapshot = tmp_path / "recovery.sqlite"
    monkeypatch.setenv("DATABASE_URL", url)
    assert main(["db", "snapshot", "--output", str(snapshot)]) == 0
    document = json.loads(Path(str(snapshot) + ".manifest.json").read_text())
    assert document["schema_revision"] == "0006_behavior_incidents"
    assert document["encrypted_by_application"] is False
    assert verify_snapshot(snapshot)["verified"] is True
    if os.name != "nt":
        assert stat.S_IMODE(snapshot.stat().st_mode) == 0o600
    target = "sqlite:///" + str(tmp_path / "host_drill_1.db")
    assert main([
        "db", "recovery-drill", "--output", str(snapshot),
        "--restore-url", target,
        "--expected-sha256", document["backup_sha256"],
        "--confirm-isolated-target",
    ]) == 0
    report = capsys.readouterr().out
    assert '"foreign_keys_verified": true' in report.lower()
    assert '"behavior_incident_audit": 1' in report
    assert '"mlops_drift_runs": 1' in report
    maker = build_sessions(target)
    with maker() as db:
        assert db.get(NetworkEvent, "recovery-ci-flow").orig_bytes == 9_000_000_000
        assert db.get(BehaviorFinding, "a" * 32).status == "resolved"
        assert db.get(BehaviorIncident, "b" * 32).assigned_to == "oncall"
    maker.kw["bind"].dispose()


def test_snapshot_rejects_overwrite_corruption_wrong_target_and_missing_consent(tmp_path):
    url = "sqlite:///" + str(tmp_path / "original.db")
    upgrade_database(url)
    snapshot = tmp_path / "snapshot.sqlite"
    receipt = create_snapshot(url, snapshot)
    approved = receipt["backup_sha256"]
    with pytest.raises(FileExistsError):
        create_snapshot(url, snapshot)
    with pytest.raises(ValueError, match="consent"):
        recovery_drill(snapshot, "sqlite:///" + str(tmp_path / "s_drill_1.db"),
                       expected_sha256=approved)
    with pytest.raises(ValueError, match="drill"):
        recovery_drill(snapshot, "sqlite:///" + str(tmp_path / "production.db"),
                       expected_sha256=approved, confirm_isolated_target=True)
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        recovery_drill(snapshot, "sqlite:///" + str(tmp_path / "s_drill_1.db"),
                       expected_sha256="0" * 64, confirm_isolated_target=True)
    snapshot.write_bytes(snapshot.read_bytes() + b"corrupt")
    with pytest.raises(ValueError, match="size mismatch"):
        verify_snapshot(snapshot)
    assert not (tmp_path / "s_drill_1.db").exists()


def test_sqlite_drill_rejects_existing_target_without_mutation(tmp_path):
    url = "sqlite:///" + str(tmp_path / "original.db")
    upgrade_database(url)
    snapshot = tmp_path / "snapshot.sqlite"
    receipt = create_snapshot(url, snapshot)
    existing = tmp_path / "already_drill_.db"
    existing.write_text("must never overwrite")
    with pytest.raises(ValueError, match="must not exist"):
        recovery_drill(
            snapshot, "sqlite:///" + str(existing),
            expected_sha256=receipt["backup_sha256"],
            confirm_isolated_target=True,
        )
    assert existing.read_text() == "must never overwrite"


@pytest.mark.skipif(not os.getenv("PG_TEST_DATABASE_URL"), reason="Real PostgreSQL CI required")
def test_postgres_native_pg_dump_restore_drill_retains_soc_audit(tmp_path):
    from sqlalchemy.engine import make_url

    admin_url = os.environ["PG_TEST_DATABASE_URL"]
    base = make_url(admin_url)
    suffix = uuid.uuid4().hex[:10]
    source_name = "networkpulse_ci_drsource_" + suffix
    target_name = "networkpulse_ci_drill_" + suffix
    # SQLAlchemy URL.__str__() REDACTS passwords by design. Explicitly
    # restore full credentials ONLY for internal DB connections, never logs.
    source = base.set(database=source_name).render_as_string(hide_password=False)
    target = base.set(database=target_name).render_as_string(hide_password=False)
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            conn.execute(text(f'CREATE DATABASE "{source_name}"'))
            conn.execute(text(f'CREATE DATABASE "{target_name}"'))
        # A distinct source DB avoids polluting the shared CI service used
        # by ingestion/concurrency tests elsewhere in the test suite.
        upgrade_database(source)
        _seed_audited_rows(source)
        backup = tmp_path / "recovery.custom"
        receipt = create_snapshot(source, backup)
        assert verify_snapshot(backup)["backup_sha256"] == receipt["backup_sha256"]
        recovered = recovery_drill(
            backup, target,
            expected_sha256=receipt["backup_sha256"],
            confirm_isolated_target=True,
        )
        assert recovered["drill"] == "completed_verified"
        assert recovered["revision"] == "0006_behavior_incidents"
        assert recovered["counts"]["behavior_incident_audit"] == 1
        assert recovered["counts"]["mlops_drift_runs"] == 1
        assert recovered["counts"]["network_events"] == 1
        with pytest.raises(ValueError, match="empty"):
            recovery_drill(
                backup, target, expected_sha256=receipt["backup_sha256"],
                confirm_isolated_target=True,
            )
        maker = build_sessions(target)
        with maker() as db:
            assert db.get(BehaviorIncident, "b" * 32).status == "resolved"
            assert db.get(BehaviorFinding, "a" * 32).assigned_to == "oncall"
            assert db.get(NetworkEvent, "recovery-ci-flow").orig_bytes == 9_000_000_000
        maker.kw["bind"].dispose()
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{target_name}" WITH (FORCE)'))
            conn.execute(text(f'DROP DATABASE IF EXISTS "{source_name}" WITH (FORCE)'))
        admin.dispose()
