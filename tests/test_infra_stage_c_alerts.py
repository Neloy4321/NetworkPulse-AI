"""Stage C synthetic alert receiver security and accounting unit tests."""
from __future__ import annotations

import threading
from http.server import ThreadingHTTPServer

import httpx
import pytest

from networkpulse.infra_stage_c_alert_fixture import (
    FixtureState, SCOPE, make_handler,
)
from networkpulse.infra_stage_c_alert_lab import require_disposable_ci


@pytest.fixture
def receiver():
    state = FixtureState("ci-only-" + "a" * 40)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _alert(fingerprint="a" * 16, alertname="NetworkPulseCISyntheticDependencyFailure",
           status="firing"):
    return {"version": "4", "status": status, "alerts": [{
        "status": status, "fingerprint": fingerprint,
        "labels": {"scope": SCOPE, "alertname": alertname},
    }]}


def test_webhook_requires_bearer_and_rejects_foreign_data(receiver):
    state, root = receiver
    auth = {"Authorization": "Bearer " + state.token}
    with httpx.Client(timeout=3) as client:
        assert client.post(root + "/webhook", json=_alert()).status_code == 401
        assert client.get(root + "/observations").status_code == 401
        assert client.post(root + "/ack", json={"fingerprint": "a" * 16}).status_code == 401
        assert client.post(root + "/webhook", json=_alert(alertname="ExternalIncident"),
                           headers=auth).status_code == 400
        assert client.post(root + "/webhook", json=_alert(),
                           headers=auth).status_code == 200
        entries = client.get(root + "/observations", headers=auth).json()["receipts"]
        assert len(entries) == 1
        assert entries[0]["status"] == "firing"
        assert entries[0]["alertname"] == "NetworkPulseCISyntheticDependencyFailure"
        assert "payload" not in entries[0]


def test_synthetic_ack_is_authenticated_and_idempotent(receiver):
    state, root = receiver
    auth = {"Authorization": "Bearer " + state.token}
    with httpx.Client(timeout=3) as client:
        assert client.post(root + "/ack", headers=auth,
                           json={"fingerprint": "b" * 16}).status_code == 404
        client.post(root + "/webhook", headers=auth, json=_alert()).raise_for_status()
        once = client.post(root + "/ack", headers=auth,
                           json={"fingerprint": "a" * 16}).json()
        again = client.post(root + "/ack", headers=auth,
                            json={"fingerprint": "a" * 16}).json()
        assert once["created"] is True and again["created"] is False
        assert once["ack"] == again["ack"]
        assert once["ack"]["kind"] == "synthetic_ci_ack_only_not_human"
        assert len(client.get(root + "/observations",
                              headers=auth).json()["acknowledgments"]) == 1


def test_only_canonical_synthetic_metrics_controlled(receiver):
    state, root = receiver
    auth = {"Authorization": "Bearer " + state.token}
    with httpx.Client(timeout=3) as client:
        assert 'networkpulse_ci_synthetic_dependency_up{scope="' in client.get(
            root + "/metrics"
        ).text
        assert client.post(root + "/control", json={
            "signal": "dependency_up", "enabled": False,
        }, headers=auth).status_code == 200
        assert 'disposable-stage-c-ci"} 0' in client.get(root + "/metrics").text
        assert client.post(root + "/control", json={
            "signal": "production", "enabled": True,
        }, headers=auth).status_code == 400
        assert client.post(root + "/control", json={
            "signal": "dependency_up", "enabled": 0,
        }, headers=auth).status_code == 400
        assert client.get(root + "/health").status_code == 200


def test_disposable_ci_guard_rejects_missing_consent_and_invalid_project(monkeypatch):
    monkeypatch.delenv("NETWORKPULSE_STAGE_C_CONFIRM", raising=False)
    with pytest.raises(ValueError, match="consent"):
        require_disposable_ci("npstagec-123456")
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("NETWORKPULSE_STAGE_C_CONFIRM", "I_ACCEPT_DISPOSABLE_STAGE_C_ALERTS")
    with pytest.raises(ValueError, match="project"):
        require_disposable_ci("production")


def test_no_legacy_ids_model_or_real_paging_path():
    from pathlib import Path
    from networkpulse import infra_stage_c_alert_fixture, infra_stage_c_alert_lab
    for module in (infra_stage_c_alert_fixture, infra_stage_c_alert_lab):
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert "from networkpulse.detector import" not in source
        assert "from networkpulse.service import" not in source
        assert "NOT_CLAIMED" in source or "not_human" in source
