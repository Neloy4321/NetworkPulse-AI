"""Fail-closed deployment and real worker-success heartbeat regression checks."""
import json
from pathlib import Path

import pytest

from networkpulse.cli import main
from networkpulse.migrations import upgrade_database
from networkpulse.ops_health import is_healthy, mark_success


def test_worker_heartbeat_is_atomic_fresh_and_not_spoofed(tmp_path, monkeypatch):
    import networkpulse.ops_health as ops
    path = tmp_path / "worker.json"
    monkeypatch.setattr(ops.time, "time", lambda: 1000.0)
    assert not is_healthy(path, "mlops", max_age_seconds=900, now=1000.0)
    mark_success(path, "mlops")
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["role"] == "mlops"
    assert is_healthy(path, "mlops", max_age_seconds=900, now=1000.0)
    assert not is_healthy(path, "behavior", max_age_seconds=900, now=1000.0)
    assert not is_healthy(path, "mlops", max_age_seconds=900, now=1901.0)
    assert not is_healthy(path, "mlops", max_age_seconds=900, now=990.0)
    path.write_text('{"role":"mlops","success_at_epoch":"1000"}')
    assert not is_healthy(path, "mlops", max_age_seconds=900, now=1000.0)
    path.write_text("[]")
    assert not is_healthy(path, "mlops", max_age_seconds=900, now=1000.0)
    with pytest.raises(ValueError, match="role"):
        mark_success(path, "unknown")
    with pytest.raises(ValueError, match="configuration"):
        is_healthy(path, "mlops", max_age_seconds=0)


def test_production_schema_check_read_only_and_fails_on_pending_migration(
        tmp_path, monkeypatch, capsys):
    url = "sqlite:///" + str(tmp_path / "preflight.db")
    monkeypatch.setenv("DATABASE_URL", url)
    assert main(["db", "check"]) == 1
    assert not Path(tmp_path / "preflight.db").with_name("preflight.db.pre-migration.bak").exists()
    assert upgrade_database(url)["revision"] == "0005_mlops_drift_runs"
    assert main(["db", "check"]) == 0
    assert '"ready": true' in capsys.readouterr().out.lower()
