"""Destructive service-drill authorization, ownership and evidence safety."""
import json

import pytest

from networkpulse import container_failover as drill


def test_double_consent_prevents_any_docker_access(monkeypatch):
    monkeypatch.delenv("NETWORKPULSE_ALLOW_ISOLATED_DOCKER_DRILL", raising=False)
    monkeypatch.setattr(drill.subprocess, "run",
                        lambda *_a, **_kw: pytest.fail("Unauthorized Docker use"))
    with pytest.raises(ValueError, match="consent"):
        drill.require_disposable_local_docker(False)
    with pytest.raises(ValueError, match="consent"):
        drill.require_disposable_local_docker(True)


def test_remote_daemon_rejected_before_invocation(monkeypatch):
    monkeypatch.setenv("NETWORKPULSE_ALLOW_ISOLATED_DOCKER_DRILL", drill.CONSENT)
    monkeypatch.setenv("DOCKER_HOST", "tcp://127.0.0.1:2375")
    monkeypatch.setattr(drill.subprocess, "run",
                        lambda *_a, **_kw: pytest.fail("Remote Docker was contacted"))
    with pytest.raises(ValueError, match="Remote"):
        drill.require_disposable_local_docker(True)


def test_nondefault_docker_context_rejected(monkeypatch):
    monkeypatch.setenv("NETWORKPULSE_ALLOW_ISOLATED_DOCKER_DRILL", drill.CONSENT)
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
    monkeypatch.setattr(
        drill.os, "stat",
        lambda *_a: type("Stat", (), {"st_mode": 0o140777})(),
    )
    monkeypatch.setattr(
        drill.subprocess, "run",
        lambda *_a, **_kw: type("Result", (), {"stdout": "remote-cluster\n"})(),
    )
    with pytest.raises(ValueError, match="non-default"):
        drill.require_disposable_local_docker(True)


def _owned(run_id="a" * 32):
    return drill.OwnedContainer(
        "b" * 64, f"networkpulse-failover-{run_id}-redis", run_id, "redis:7-alpine",
    )


def test_ownership_label_mismatch_prevents_any_destructive_docker_call(monkeypatch):
    item = _owned()
    called = []

    def fake(*args, **_kwargs):
        called.append(args)
        if args[0] != "inspect":
            pytest.fail("Dangerous Docker command reached")
        return json.dumps([{
            "Id": item.container_id, "Name": "/" + item.name,
            "Config": {"Labels": {
                drill.LABEL_OWNER: "false",
                drill.LABEL_RUN: item.run_id,
            }, "Image": item.image},
        }])

    monkeypatch.setattr(drill, "_docker", fake)
    lab = drill.DisposableLab(item.run_id)
    lab.owned.append(item)
    with pytest.raises(ValueError, match="ownership"):
        lab.kill(item)
    with pytest.raises(ValueError, match="ownership"):
        lab.restart(item)
    with pytest.raises(ValueError, match="ownership"):
        lab.cleanup()
    assert [args[0] for args in called] == ["inspect"] * 3


def test_verified_lab_only_stops_starts_and_cleans_its_own_id(monkeypatch):
    item = _owned("e" * 32)
    calls = []

    def fake(*args, **_kwargs):
        calls.append(args)
        if args[0] == "inspect":
            return json.dumps([{
                "Id": item.container_id, "Name": "/" + item.name,
                "Config": {"Labels": {
                    drill.LABEL_OWNER: "true",
                    drill.LABEL_RUN: item.run_id,
                }, "Image": item.image},
            }])
        return ""

    monkeypatch.setattr(drill, "_docker", fake)
    lab = drill.DisposableLab(item.run_id)
    lab.owned.append(item)
    lab.kill(item)
    lab.restart(item)
    lab.cleanup()
    actual = [args for args in calls if args[0] != "inspect"]
    assert [args[0] for args in actual] == ["kill", "start", "rm"]
    assert all(args[-1] == item.container_id for args in actual)


def test_public_bound_port_is_rejected(monkeypatch):
    item = _owned()
    monkeypatch.setattr(drill, "verified_owned", lambda _item: None)
    monkeypatch.setattr(drill, "_docker", lambda *_args: "0.0.0.0:45000")
    with pytest.raises(RuntimeError, match="local-only"):
        drill._published_loopback_port(item, 6379)


def test_docker_error_cannot_leak_password(monkeypatch):
    monkeypatch.setattr(
        drill.subprocess, "run", lambda *_a, **_kw: type("Result", (), {
            "returncode": 1, "stderr": "POSTGRES_PASSWORD=secret",
            "stdout": "",
        })(),
    )
    with pytest.raises(RuntimeError) as error:
        drill._docker("run", "-e", "POSTGRES_PASSWORD=secret")
    assert "secret" not in str(error.value)


def test_report_is_immutable_and_owner_only(tmp_path):
    path = tmp_path / "evidence.json"
    drill.write_report(path, {"status": "passed", "scope": "disposable_lab"})
    assert (path.stat().st_mode & 0o777) == 0o600
    with pytest.raises(FileExistsError):
        drill.write_report(path, {"status": "failed"})
    assert json.loads(path.read_text())["status"] == "passed"
