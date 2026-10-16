"""No disruptive Docker calls outside explicit disposable CI; live E2E is CI only."""
from __future__ import annotations

import json

import pytest

from networkpulse import infra_stage_b_restart as drill


def test_disposable_ci_requires_explicit_authentication(monkeypatch):
    monkeypatch.delenv("NETWORKPULSE_STAGE_B_RESTART_CONFIRM", raising=False)
    with pytest.raises(ValueError, match="consent"):
        drill.require_disposable_ci("npstageb-123456", True)
    monkeypatch.setenv("NETWORKPULSE_STAGE_B_RESTART_CONFIRM", drill.CONSENT)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    with pytest.raises(ValueError, match="GitHub Actions"):
        drill.require_disposable_ci("npstageb-123456", True)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("CI", "true")
    with pytest.raises(ValueError, match="scoped"):
        drill.require_disposable_ci("production", True)
    monkeypatch.setenv("DOCKER_HOST", "tcp://unsafe:2375")
    with pytest.raises(ValueError, match="Remote"):
        drill.require_disposable_ci("npstageb-123456", True)


def test_owned_container_refuses_foreign_labels_and_ports(monkeypatch):
    project = "npstageb-123456"
    fake_id = "a" * 64
    fixture = [{
        "Id": fake_id,
        "Config": {"Labels": {
            "com.docker.compose.project": "some-other-project",
            "com.docker.compose.service": "db",
        }, "Image": "postgres:16-alpine"},
        "NetworkSettings": {"Ports": {"5432/tcp": [
            {"HostIp": "127.0.0.1", "HostPort": "15432"},
        ]}},
    }]

    def docker(*args, **_kwargs):
        return fake_id if "ps" in args else json.dumps(fixture)

    monkeypatch.setattr(drill, "_docker", docker)
    with pytest.raises(ValueError, match="ownership"):
        drill.owned_container(project, "db")
    fixture[0]["Config"]["Labels"]["com.docker.compose.project"] = project
    fixture[0]["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostIp"] = "0.0.0.0"
    with pytest.raises(ValueError, match="loopback"):
        drill.owned_container(project, "db")
    fixture[0]["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostIp"] = "127.0.0.1"
    assert drill.owned_container(project, "db") == fake_id
    with pytest.raises(ValueError, match="Unsupported"):
        drill.owned_container(project, "api")


def test_kill_refuses_missing_outage_observation(monkeypatch):
    calls = []
    monkeypatch.setattr(drill, "owned_container", lambda *_: "a" * 64)
    monkeypatch.setattr(drill, "_port_down", lambda _: False)
    monkeypatch.setattr(drill.time, "sleep", lambda _: None)

    def docker(*args, **_kwargs):
        calls.append(args)
        return "true"

    monkeypatch.setattr(drill, "_docker", docker)
    with pytest.raises(RuntimeError, match="stopped state not observed"):
        drill.kill_and_recover("npstageb-123456", "db", lambda: True)
    assert calls[0][:2] == ("kill", "--signal=KILL")
    assert not any(x[0] == "start" for x in calls)


def test_aof_requires_fsync_acknowledgement():
    class FakeCache:
        def __init__(self, answer):
            self.answer = answer

        def execute_command(self, *args):
            assert args == ("WAITAOF", 1, 0, 5000)
            return self.answer

    drill._await_aof(FakeCache([1, 0]))
    with pytest.raises(RuntimeError, match="AOF"):
        drill._await_aof(FakeCache([0, 0]))


def test_no_model_or_real_data_imported():
    from pathlib import Path
    source = Path(drill.__file__).read_text()
    assert "from networkpulse.detector import" not in source
    assert "from networkpulse.service import" not in source
    assert "NETWORKPULSE_STAGE_B_RESTART_CONFIRM" in source
    assert "NOT_CLAIMED" in source
