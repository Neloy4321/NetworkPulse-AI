"""Regression: operational SQL MLOps drift evidence, never synthetic accuracy claims."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from networkpulse.mlops_monitor import completed_hour, run_monitor
from networkpulse.model_registry import sha256
from networkpulse.service import ingest
from networkpulse.storage import MLOpsDriftRun, build_sessions


def test_live_monitor_pinned_model_lineage_immutable_and_fail_closed(
        app_settings, trained_detector, samples, client):
    maker = build_sessions(app_settings.database_url)
    ordered = samples[-80:]
    start = ordered[0].timestamp - timedelta(seconds=1)
    end = ordered[-1].timestamp + timedelta(minutes=5)
    expected = sha256(app_settings.model_path)
    try:
        with maker() as db:
            assert ingest(db, trained_detector, ordered[:60])["inserted"] == 60
        with maker() as db:
            first = run_monitor(db, model_path=app_settings.model_path,
                                expected_sha256=expected, start=start, end=end)
            assert first["created"] is True
            assert first["flow_count"] == 60
        with maker() as db:
            second = run_monitor(db, model_path=app_settings.model_path,
                                 expected_sha256=expected, start=start, end=end)
            assert second["created"] is False
            assert second["id"] == first["id"]
            assert db.scalar(select(func.count(MLOpsDriftRun.id))) == 1
            stored = db.get(MLOpsDriftRun, first["id"])
            assert stored.report["data_lineage"]["exact_committed_rows"] == 60
            assert stored.report["data_lineage"]["labels_available"] is False
            assert stored.report["data_lineage"]["complete_window_no_sampling"]
            assert "labeled_window_diagnostics" not in stored.report
            assert "src_ip" not in str(stored.report)
            assert "dst_ip" not in str(stored.report)
        assert client.get("/api/v1/mlops/drift-runs").status_code == 200
        listed = client.get("/api/v1/mlops/drift-runs").json()
        assert listed["runs"][0]["id"] == first["id"]
        assert listed["runs"][0]["model_sha256"] == expected
        with maker() as db:
            assert ingest(db, trained_detector, ordered[60:])["inserted"] == 20
        with maker() as db:
            later = run_monitor(db, model_path=app_settings.model_path,
                                expected_sha256=expected, start=start, end=end)
            assert later["created"] is True
            assert later["flow_count"] == 80
            assert later["id"] != first["id"]
            assert db.scalar(select(func.count(MLOpsDriftRun.id))) == 2
        with maker() as db:
            with pytest.raises(ValueError, match="checksum"):
                run_monitor(db, model_path=app_settings.model_path,
                            expected_sha256="0"*64, start=start, end=end)
            with pytest.raises(RuntimeError, match="max_rows"):
                run_monitor(db, model_path=app_settings.model_path,
                            expected_sha256=expected, start=start, end=end,
                            max_rows=30)
            with pytest.raises(ValueError, match="timezone"):
                run_monitor(db, model_path=app_settings.model_path,
                            expected_sha256=expected, start=start.replace(tzinfo=None),
                            end=end)
            sparse = run_monitor(db, model_path=app_settings.model_path,
                                 expected_sha256=expected, start=start-timedelta(days=2),
                                 end=start-timedelta(days=2)+timedelta(hours=1))
            assert sparse["status"] == "insufficient_data"
            assert sparse["created"] is False
    finally:
        maker.kw["bind"].dispose()


def test_closed_hour_watermark_and_query_validation(client):
    start, end = completed_hour(
        now=datetime(2026, 10, 14, 12, 9, tzinfo=timezone.utc),
        delay_minutes=10,
    )
    assert start.isoformat() == "2026-10-14T10:00:00+00:00"
    assert end.isoformat() == "2026-10-14T11:00:00+00:00"
    assert client.get("/api/v1/mlops/drift-runs?limit=101").status_code == 422
