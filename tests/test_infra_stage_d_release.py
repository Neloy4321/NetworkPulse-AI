"""Unit security and route-state tests for Stage D (no Docker mutations)."""
from __future__ import annotations

import json
import threading
from http.server import ThreadingHTTPServer

import httpx
import pytest

from networkpulse.infra_stage_d_release_fixture import (
    SCOPE, digest, make_handler, route_target,
)
from networkpulse.infra_stage_d_release_lab import (
    _preflight, _switch, owned_service, require_disposable_ci,
)


@pytest.fixture
def service():
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler("stable"))
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=4)


def test_real_http_fixture_identity_and_no_ml(service):
    with httpx.Client(timeout=3) as client:
        result = client.get(service + "/release")
        assert result.status_code == 200
        assert result.json() == {
            "scope": SCOPE, "model_loaded": False, "release": "stable",
            "sha256": digest("stable"), "ready": True,
        }
        assert client.get(service + "/score").status_code == 404


def test_preflight_really_rejects_wrong_pin_before_route_change(service, monkeypatch):
    from networkpulse import infra_stage_d_release_lab as lab
    monkeypatch.setitem(lab.ENDPOINTS, "stable", service)
    with httpx.Client(timeout=3, trust_env=False) as client:
        assert _preflight(client, "stable", digest("stable"))["release"] == "stable"
        with pytest.raises(ValueError, match="fingerprint mismatch"):
            _preflight(client, "stable", "0" * 64)
        with pytest.raises(ValueError, match="Invalid pinned"):
            _preflight(client, "production", digest("stable"))


def test_atomic_transition_has_strict_compare_and_swap(tmp_path):
    path = tmp_path / "active"
    path.write_text("stable\n")
    assert route_target(path) == "stable"
    _switch(tmp_path, "candidate", expected_previous="stable")
    assert route_target(path) == "candidate"
    with pytest.raises(RuntimeError, match="Unexpected active"):
        _switch(tmp_path, "candidate", expected_previous="stable")
    _switch(tmp_path, "stable", expected_previous="candidate")
    assert route_target(path) == "stable"


def test_route_tamper_or_symlink_refuses_transition(tmp_path):
    active = tmp_path / "active"
    active.write_text("something-unapproved\n")
    with pytest.raises(ValueError, match="Unknown"):
        route_target(active)
    with pytest.raises(RuntimeError, match="Unexpected"):
        _switch(tmp_path, "candidate", expected_previous="stable")
    active.unlink()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_text("stable\n")
    active.symlink_to(elsewhere)
    with pytest.raises(RuntimeError, match="Unexpected"):
        _switch(tmp_path, "candidate", expected_previous="stable")
    assert elsewhere.read_text() == "stable\n"


def test_ci_guard_refuses_consent_and_non_disposable_target(monkeypatch, tmp_path):
    monkeypatch.delenv("NETWORKPULSE_STAGE_D_CONFIRM", raising=False)
    with pytest.raises(ValueError, match="consent"):
        require_disposable_ci("npstaged-123456", tmp_path)
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("NETWORKPULSE_STAGE_D_CONFIRM",
                       "I_ACCEPT_DISPOSABLE_STAGE_D_ROLLBACK")
    with pytest.raises(ValueError, match="project"):
        require_disposable_ci("networkpulse-production", tmp_path)


def test_container_ownership_refuses_foreign_service_and_labels(monkeypatch):
    import networkpulse.infra_stage_d_release_lab as lab
    with pytest.raises(ValueError, match="Only disposable"):
        owned_service("npstaged-123456", "stable")
    fixture_id = "a" * 64
    record = [{
        "Id": fixture_id,
        "Config": {"Image": "python:3.12-alpine", "Labels": {
            "com.docker.compose.project": "foreign",
            "com.docker.compose.service": "candidate",
        }},
        "NetworkSettings": {"Ports": {"8000/tcp": [
            {"HostIp": "127.0.0.1", "HostPort": "18812"},
        ]}},
    }]

    monkeypatch.setattr(lab, "_docker", lambda *a: fixture_id if "ps" in a
                        else json.dumps(record))
    with pytest.raises(ValueError, match="ownership"):
        owned_service("npstaged-123456", "candidate")
    record[0]["Config"]["Labels"]["com.docker.compose.project"] = "npstaged-123456"
    assert owned_service("npstaged-123456", "candidate") == fixture_id
    record[0]["NetworkSettings"]["Ports"]["8000/tcp"][0]["HostIp"] = "0.0.0.0"
    with pytest.raises(ValueError, match="ownership"):
        owned_service("npstaged-123456", "candidate")


def test_no_production_service_or_model_import():
    from pathlib import Path
    from networkpulse import infra_stage_d_release_lab, infra_stage_d_release_fixture
    for module in (infra_stage_d_release_lab, infra_stage_d_release_fixture):
        contents = Path(module.__file__).read_text(encoding="utf-8")
        assert "from networkpulse.service import" not in contents
        assert "from networkpulse.detector import" not in contents
        assert "NOT_CLAIMED" in contents or "ephemeral_nonml_stage_d_ci" in contents
