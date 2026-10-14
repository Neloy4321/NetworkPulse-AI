"""Release-to-runtime guardrails for API, streaming and MLOps processes."""
from dataclasses import replace
import json

import pytest

from networkpulse.cli import main
from networkpulse.deployment_preflight import (
    require_runtime_release, verify_deployment_model,
)
from networkpulse.model_registry import ModelRegistry, sha256
from networkpulse.streaming.redis_streams import process_events


@pytest.fixture
def active_release(app_settings, tmp_path):
    from networkpulse.detector import Detector
    model = Detector.load(app_settings.model_path)
    model.metadata["source"] = "trusted_ci_fixture_not_independently_validated"
    model.save(app_settings.model_path)
    registry = ModelRegistry(tmp_path / "registry")
    registry.register("candidate-ci", app_settings.model_path)
    registry.promote("candidate-ci", app_settings.model_path)
    return registry, app_settings.model_path, sha256(app_settings.model_path)


def test_readonly_preflight_checks_active_registry_pin_and_feature(active_release):
    registry, deployed, digest = active_release
    result = verify_deployment_model(
        model_path=deployed, expected_sha256=digest, registry_root=registry.root,
    )
    assert result["verified"] and result["active"] == "candidate-ci"
    assert result["sha256"] == digest
    assert main(["model-registry", "preflight", "--root", str(registry.root),
                 "--active", str(deployed), "--expected-sha256", digest]) == 0


def test_preflight_refuses_wrong_pin_and_tampered_deployed_or_registry(active_release):
    registry, deployed, digest = active_release
    def check(pin=digest):
        return verify_deployment_model(
            model_path=deployed, expected_sha256=pin, registry_root=registry.root,
        )
    with pytest.raises(ValueError, match="NP-REL-001"):
        check("not-a-sha")
    with pytest.raises(ValueError, match="NP-REL-003"):
        check("0" * 64)
    deployed.write_bytes(deployed.read_bytes() + b"tampered-deployed")
    with pytest.raises(ValueError, match="checksum"):
        check()
    # Restore deployed artifact from the registered candidate.
    import shutil
    shutil.copyfile(registry.root / "candidate-ci.joblib", deployed)
    assert check()["verified"]
    source = registry.root / "candidate-ci.joblib"
    source.write_bytes(source.read_bytes() + b"tampered-registry")
    with pytest.raises(ValueError, match="integrity"):
        check()


def test_preflight_refuses_journal_feature_mismatch_and_demo(active_release):
    registry, deployed, digest = active_release
    def check():
        return verify_deployment_model(
            model_path=deployed, expected_sha256=digest, registry_root=registry.root,
        )
    registry.journal.write_text('{"unfinished":true}')
    with pytest.raises(RuntimeError, match="journal"):
        check()
    registry.journal.unlink()
    data = json.loads(registry.catalog.read_text())
    data["candidates"]["candidate-ci"]["feature_version"] = "outdated"
    registry.catalog.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="NP-REL-004"):
        check()
    from networkpulse.features import FEATURE_VERSION
    data["candidates"]["candidate-ci"]["feature_version"] = FEATURE_VERSION
    registry.catalog.write_text(json.dumps(data))
    data["candidates"]["candidate-ci"]["synthetic_only"] = True
    registry.catalog.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="NP-REL-005"):
        check()


def test_production_rejects_missing_registry_and_worker_does_not_dequeue(
    app_settings, monkeypatch,
):
    settings = replace(app_settings, deployment_mode="production",
                       model_sha256=sha256(app_settings.model_path))
    monkeypatch.delenv("NETWORKPULSE_MODEL_REGISTRY_ROOT", raising=False)
    with pytest.raises(ValueError, match="NP-REL-002"):
        require_runtime_release(settings)

    class NoQueueAccess:
        def initialize(self):
            raise AssertionError("dequeued before verifying release")
    with pytest.raises(ValueError, match="NP-REL-002"):
        process_events(NoQueueAccess(), "preflight-ci", settings=settings, once=True)


def test_development_opt_in_enforces_registry(active_release, app_settings, monkeypatch):
    registry, deployed, digest = active_release
    settings = replace(app_settings, model_sha256=digest)
    monkeypatch.delenv("NETWORKPULSE_MODEL_REGISTRY_ROOT", raising=False)
    assert require_runtime_release(settings) is None
    monkeypatch.setenv("NETWORKPULSE_MODEL_REGISTRY_ROOT", str(registry.root))
    assert require_runtime_release(settings)["verified"]
    with pytest.raises(ValueError, match="NP-REL-003"):
        require_runtime_release(replace(settings, model_sha256="f" * 64))
