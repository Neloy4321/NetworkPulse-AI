"""Durable behavior-case pipeline: real storage, UTC boundaries, SOC audit and RBAC."""
from datetime import datetime, timezone

from networkpulse.behavior_cases import finding_id, materialize_findings
from networkpulse.detector import Detector
from networkpulse.schemas import FlowEvent
from networkpulse.service import ingest
from networkpulse.storage import BehaviorFinding, BehaviorFindingAudit, build_sessions


def _traffic(sample, n=5):
    template = sample.model_dump(mode="json")
    events = []
    for i in range(n):
        row = {
            **template, "source": "canonical",
            "timestamp": datetime(2026, 10, 14, 12, 0, 10 + i,
                                  tzinfo=timezone.utc).isoformat(),
            "src_ip": "198.51.100.25",
            "dst_ip": f"203.0.113.{10 + i % 3}",
            "dst_port": 8000 + i,
            "proto": "tcp",
        }
        events.append(FlowEvent.model_validate(row))
    return events


def test_case_materialization_is_replay_safe_and_human_state_survives(
        app_settings, client, samples):
    maker = build_sessions(app_settings.database_url)
    model = Detector.load(app_settings.model_path)
    end = datetime(2026, 10, 14, 12, 5, tzinfo=timezone.utc)
    initial = _traffic(samples[0], 4)
    try:
        with maker() as db:
            assert ingest(db, model, initial)["inserted"] == 4
        with maker() as db:
            first = materialize_findings(
                db, until=end, lateness_minutes=0, lookback_minutes=5,
                min_ports=3, min_destinations=3,
            )
            again = materialize_findings(
                db, until=end, lateness_minutes=0, lookback_minutes=5,
                min_ports=3, min_destinations=3,
            )
            assert first["candidate_upserts"] == again["candidate_upserts"] == 1
            case = db.get(BehaviorFinding, finding_id(
                "198.51.100.25", datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc),
            ))
            assert case and case.flow_count == 4
            assert case.destination_ports == 4 and case.destination_hosts == 3
            assert set(case.patterns) == {"port_sweep_like", "destination_fanout_like"}
            assert case.status == "open"
        finding_id_value = finding_id(
            "198.51.100.25", datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc),
        )
        url = "/api/v1/intelligence/findings"
        listing = client.get(url)
        assert listing.status_code == 200
        assert len(listing.json()["findings"]) == 1
        assert client.patch(
            url + "/" + finding_id_value,
            json={"status": "investigating", "assigned_to": "lead-analyst",
                  "note": "Source-window correlations reviewed"},
        ).status_code == 401
        changed = client.patch(
            url + "/" + finding_id_value,
            json={"status": "resolved", "assigned_to": "lead-analyst",
                  "note": "Activity approved by customer"},
            headers={"X-API-Key": app_settings.api_key},
        )
        assert changed.status_code == 200, changed.text
        assert changed.json()["status"] == "resolved"
        assert changed.json()["assigned_to"] == "lead-analyst"
        history = client.get(url + "/" + finding_id_value + "/history")
        assert history.status_code == 200
        assert history.json()[0]["actor"] == "local-operator"
        with maker() as db:
            # A late flow increases counters but NEVER reopens resolved cases.
            assert ingest(db, model, _traffic(samples[0], 5))["inserted"] == 1
        with maker() as db:
            materialize_findings(
                db, until=end, lateness_minutes=0, lookback_minutes=5,
                min_ports=3, min_destinations=3,
            )
            case = db.get(BehaviorFinding, finding_id_value)
            assert case.flow_count == 5
            assert case.status == "resolved"
            assert case.assigned_to == "lead-analyst"
            assert db.query(BehaviorFinding).count() == 1
            assert db.query(BehaviorFindingAudit).count() == 1
        for invalid in (
            {"status": None, "note": "bad change"},
            {"note": "missing action"},
            {"status": "resolved", "note": "no"},
        ):
            response = client.patch(
                url + "/" + finding_id_value, json=invalid,
                headers={"X-API-Key": app_settings.api_key},
            )
            assert response.status_code == 422
        assert client.get(url, params={"source_ip": "not-ip"}).status_code == 422
    finally:
        maker.kw["bind"].dispose()


def test_case_processor_excludes_unfinished_utc_window(app_settings, samples):
    maker = build_sessions(app_settings.database_url)
    model = Detector.load(app_settings.model_path)
    try:
        with maker() as db:
            ingest(db, model, _traffic(samples[0], 5))
        with maker() as db:
            result = materialize_findings(
                db, until=datetime(2026, 10, 14, 12, 4, 59, tzinfo=timezone.utc),
                lateness_minutes=0, lookback_minutes=5,
                min_ports=3, min_destinations=3,
            )
            assert result["candidate_upserts"] == 0
            assert db.query(BehaviorFinding).count() == 0
            result = materialize_findings(
                db, until=datetime(2026, 10, 14, 12, 5, tzinfo=timezone.utc),
                lateness_minutes=0, lookback_minutes=5,
                min_ports=3, min_destinations=3,
            )
            assert result["candidate_upserts"] == 1
        with maker() as db:
            assert db.query(BehaviorFinding).count() == 1
    finally:
        maker.kw["bind"].dispose()
