"""Durable source-hour incident integration, evidence timeline and review RBAC."""
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import func, select

from networkpulse.incidents import incident_id, materialize_incidents
from networkpulse.storage import (
    BehaviorFinding, BehaviorIncident, BehaviorIncidentAudit, build_sessions,
)


def _insert_window(session, source: str, when: datetime, number: int,
                   signals: list[str] | None = None):
    session.add(BehaviorFinding(
        id=("%032x" % number), source_ip=source,
        window_start=when, window_minutes=5,
        patterns=signals or ["port_sweep_like"], flow_count=12,
        destination_ports=12, destination_hosts=3,
        flagged_flows=2, severity="medium",
        status="open", assigned_to=None,
    ))
    session.commit()


def test_multi_window_incident_lifecycle_and_api(app_settings, client):
    maker = build_sessions(app_settings.database_url)
    hour = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)
    src = "198.51.100.43"
    identity = incident_id(src, hour)
    try:
        with maker() as session:
            _insert_window(session, src, hour, 101)
            _insert_window(session, src, hour + timedelta(minutes=5), 102,
                           ["destination_fanout_like"])
        with maker() as session:
            result = materialize_incidents(
                session, until=hour + timedelta(minutes=10),
                lookback_hours=1, lateness_minutes=0,
            )
            assert result["candidate_upserts"] == 1
            incident = session.get(BehaviorIncident, identity)
            assert incident.window_count == 2
            assert incident.total_flows == 24
            assert incident.finding_ids == ["%032x" % 101, "%032x" % 102]
            assert incident.patterns == ["destination_fanout_like", "port_sweep_like"]
        base = "/api/v1/intelligence/incidents"
        resp = client.get(base)
        assert resp.status_code == 200
        assert resp.json()["incidents"][0]["id"] == identity
        assert client.get(base + "/" + identity + "/evidence").json()["timeline"]
        assert len(client.get(base + "/" + identity + "/evidence").json()["timeline"]) == 2
        assert client.patch(base + "/" + identity, json={
            "status": "resolved", "note": "Reviewed authorized traffic source"
        }).status_code == 401
        changed = client.patch(
            base + "/" + identity,
            json={"status": "resolved", "assigned_to": "oncall-analyst",
                  "note": "Operator reviewed the hourly network evidence"},
            headers={"X-API-Key": app_settings.api_key},
        )
        assert changed.status_code == 200, changed.text
        assert changed.json()["status"] == "resolved"
        assert changed.json()["assigned_to"] == "oncall-analyst"
        audit = client.get(base + "/" + identity + "/history")
        assert audit.status_code == 200
        assert len(audit.json()) == 1
        assert audit.json()[0]["actor"] == "local-operator"
        with maker() as session:
            _insert_window(session, src, hour + timedelta(minutes=10), 103,
                           ["connection_burst_like"])
        with maker() as session:
            twice = materialize_incidents(
                session, until=hour + timedelta(minutes=15),
                lookback_hours=1, lateness_minutes=0,
            )
            assert twice["candidate_upserts"] == 1
            materialize_incidents(
                session, until=hour + timedelta(minutes=15),
                lookback_hours=1, lateness_minutes=0,
            )
            incident = session.get(BehaviorIncident, identity)
            assert incident.window_count == 3
            assert incident.total_flows == 36
            assert incident.status == "resolved"
            assert incident.assigned_to == "oncall-analyst"
            assert session.scalar(select(func.count(BehaviorIncident.id))) == 1
            assert session.scalar(select(func.count(BehaviorIncidentAudit.id))) == 1
        assert len(client.get(base + "/" + identity + "/evidence").json()["timeline"]) == 3
        assert client.get(base, params={"source_ip": "not-ip"}).status_code == 422
        assert client.get(base + "/nonexistent/evidence").status_code == 404
        assert client.patch(
            base + "/" + identity,
            json={"status": None, "note": "Invalid null status"},
            headers={"X-API-Key": app_settings.api_key},
        ).status_code == 422
    finally:
        maker.kw["bind"].dispose()


def test_incomplete_hour_boundary_is_safe_and_case_is_source_scoped(app_settings):
    maker = build_sessions(app_settings.database_url)
    start = datetime(2026, 10, 14, 13, 0, tzinfo=timezone.utc)
    try:
        with maker() as session:
            _insert_window(session, "198.51.100.48", start, 201)
            _insert_window(session, "198.51.100.48", start + timedelta(minutes=5), 202)
            _insert_window(session, "198.51.100.49", start, 203)
        with maker() as session:
            first = materialize_incidents(
                session, until=start + timedelta(minutes=9),
                lookback_hours=1, lateness_minutes=0,
            )
            assert first["candidate_upserts"] == 0
            next_time = materialize_incidents(
                session, until=start + timedelta(minutes=10),
                lookback_hours=1, lateness_minutes=0,
            )
            assert next_time["candidate_upserts"] == 1
            assert session.scalar(select(func.count(BehaviorIncident.id))) == 1
        with maker() as session:
            _insert_window(session, "198.51.100.48", start + timedelta(hours=1), 204)
            _insert_window(session, "198.51.100.48", start + timedelta(hours=1, minutes=5), 205)
        with maker() as session:
            materialize_incidents(
                session, until=start + timedelta(hours=1, minutes=10),
                lookback_hours=2, lateness_minutes=0,
            )
            assert session.scalar(select(func.count(BehaviorIncident.id))) == 2
        with pytest.raises(ValueError, match="timezone-aware"):
            with maker() as session:
                materialize_incidents(
                    session, until=start.replace(tzinfo=None),
                )
    finally:
        maker.kw["bind"].dispose()


@pytest.mark.skipif(
    not __import__("os").getenv("PG_TEST_DATABASE_URL"),
    reason="PostgreSQL CI service required",
)
def test_postgres_incident_multiworker_collision_safe():
    from networkpulse.migrations import upgrade_database
    from networkpulse.storage import build_sessions
    import os

    url = os.environ["PG_TEST_DATABASE_URL"]
    upgrade_database(url)
    maker = build_sessions(url)
    start = datetime(2026, 10, 14, 14, 0, tzinfo=timezone.utc)
    source = "198.51.100.99"
    try:
        with maker() as session:
            _insert_window(session, source, start, 301)
            _insert_window(session, source, start + timedelta(minutes=5), 302)
        def worker(_):
            with maker() as session:
                return materialize_incidents(
                    session, until=start + timedelta(minutes=10),
                    lookback_hours=1, lateness_minutes=0,
                )
        with ThreadPoolExecutor(max_workers=3) as executor:
            results = list(executor.map(worker, range(3)))
        assert all(x["candidate_upserts"] >= 1 for x in results)
        with maker() as session:
            incident = session.get(BehaviorIncident, incident_id(source, start))
            assert incident is not None and incident.window_count == 2
            assert session.scalar(select(func.count(BehaviorIncident.id)).where(
                BehaviorIncident.source_ip == source,
            )) == 1
    finally:
        maker.kw["bind"].dispose()
