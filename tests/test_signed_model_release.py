"""Signed release approvals and crash/concurrent registry rollout safety."""
import base64
import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)

import networkpulse.model_registry as registry_module
from networkpulse.cli import main
from networkpulse.detector import train
from networkpulse.model_registry import ModelRegistry, sha256
from networkpulse.release_approval import canonical_bytes, verify_signed_approval
from networkpulse.simulator import sample_flows


@pytest.fixture
def trusted_signer(tmp_path):
    secret = Ed25519PrivateKey.generate()  # CI-only volatile key; never committed.
    trusted = tmp_path / "externally-provisioned-keys.json"
    trust_record = {
        "schema_version": 1,
        "keys": [{
            "key_id": "ci-security-approver",
            "enabled": True,
            "ed25519_public_key_base64": base64.b64encode(
                secret.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            ).decode(),
        }],
    }
    trusted.write_text(json.dumps(trust_record))

    def sign(payload, *, key_id="ci-security-approver"):
        envelope = {
            "schema_version": 1, "key_id": key_id,
            "payload": payload,
            "signature": base64.b64encode(secret.sign(canonical_bytes(payload))).decode(),
        }
        document = tmp_path / "signed-approval.json"
        document.write_text(json.dumps(envelope))
        return document
    return sign, trusted, trust_record


def _payload(digest, *, prior=None, action="promote", change_id="ci-change-001"):
    now = datetime.now(timezone.utc)
    return {
        "candidate_sha256": digest,
        "previous_active": prior,
        "operation": action,
        "change_id": change_id,
        "independent_site_verified": True,
        "live_sensor_contract_verified": True,
        "training_test_leakage_audited": True,
        "approved_by": "CI trusted reviewer, not a real field approval",
        "evaluation": {
            "benign_count": 400, "attack_count": 40, "false_positives": 1,
        },
        "issued_at_utc": (now - timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
        "expires_at_utc": (now + timedelta(days=2)).isoformat().replace("+00:00", "Z"),
    }


def _registry_two(tmp_path):
    events = sample_flows(360, seed=914)
    a = train(events, seed=914, source="trusted_real_capture_fixture")
    b = train(events, seed=916, source="trusted_real_capture_fixture")
    pa, pb = tmp_path / "a.joblib", tmp_path / "b.joblib"
    a.save(pa)
    b.save(pb)
    registry = ModelRegistry(tmp_path / "registry")
    registry.register("baseline", pa)
    registry.register("challenger", pb)
    return registry, pa, pb


def test_tampered_revoked_unknown_and_expired_signature_fail_closed(tmp_path, trusted_signer):
    sign, trusted, config = trusted_signer
    data = _payload("a" * 64)
    path = sign(data)
    verified = verify_signed_approval(path, trusted)
    assert verified["signature_verified"] and verified["signer_key_id"] == "ci-security-approver"
    envelope = json.loads(path.read_text())
    envelope["payload"]["candidate_sha256"] = "b" * 64
    path.write_text(json.dumps(envelope))
    with pytest.raises(ValueError, match="signature"):
        verify_signed_approval(path, trusted)
    sign(data, key_id="unknown-key")
    with pytest.raises(ValueError, match="trusted"):
        verify_signed_approval(path, trusted)
    sign(data)
    config["keys"][0]["enabled"] = False
    trusted.write_text(json.dumps(config))
    with pytest.raises(ValueError, match="revoked"):
        verify_signed_approval(path, trusted)
    config["keys"][0]["enabled"] = True
    trusted.write_text(json.dumps(config))
    data["expires_at_utc"] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    sign(data)
    with pytest.raises(ValueError, match="expired"):
        verify_signed_approval(path, trusted)


def test_signed_promotion_rollback_and_deployed_integrity(tmp_path, trusted_signer):
    sign, trust, _ = trusted_signer
    registry, first, second = _registry_two(tmp_path)
    deployed = tmp_path / "current.joblib"
    # Plain JSON and no trusted signing key cannot authorize prod use.
    data = _payload(sha256(first))
    path = sign(data)
    with pytest.raises(ValueError, match="trusted"):
        registry.promote("baseline", deployed, production=True, evidence_path=path)
    registry.promote("baseline", deployed, production=True,
                     evidence_path=path, trust_store=trust)
    assert registry.verify_active(deployed)["sha256"] == sha256(first)
    signed_new = sign(_payload(sha256(second), prior="baseline", change_id="ci-change-002"))
    registry.promote("challenger", deployed, production=True,
                     evidence_path=signed_new, trust_store=trust)
    assert registry.verify_active(deployed)["sha256"] == sha256(second)
    rolled_back_approval = sign(_payload(
        sha256(first), prior="challenger", action="rollback", change_id="ci-change-003"
    ))
    registry.rollback(deployed, production=True,
                      evidence_path=rolled_back_approval, trust_store=trust)
    assert registry.verify_active(deployed)["sha256"] == sha256(first)
    with pytest.raises(ValueError, match="already consumed"):
        registry.promote("challenger", deployed, production=True,
                         evidence_path=signed_new, trust_store=trust)
    with pytest.raises(ValueError, match="previous"):
        registry.rollback(deployed)
    deployed.write_bytes(deployed.read_bytes() + b"altered")
    with pytest.raises(ValueError, match="checksum"):
        registry.verify_active(deployed)
    with pytest.raises(ValueError, match="checksum"):
        registry.promote("challenger", deployed)


def test_registry_failure_rolls_back_replaced_artifact(tmp_path, monkeypatch):
    registry, first, second = _registry_two(tmp_path)
    deployed = tmp_path / "deployed.joblib"
    registry.promote("baseline", deployed)
    saved = sha256(deployed)
    real_write = registry_module._write_json
    def fail_catalog_once(path, value):
        if path == registry.catalog:
            raise OSError("simulated filesystem catalog write failure")
        return real_write(path, value)
    monkeypatch.setattr(registry_module, "_write_json", fail_catalog_once)
    with pytest.raises(OSError, match="simulated"):
        registry.promote("challenger", deployed)
    assert sha256(deployed) == saved
    assert not registry.journal.exists()
    assert registry.verify_active(deployed)["active"] == "baseline"
    registry.journal.write_text('{"action": "interrupted"}')
    with pytest.raises(RuntimeError, match="journal"):
        registry.promote("challenger", deployed)
    with pytest.raises(RuntimeError, match="journal"):
        registry.verify_active(deployed)


def test_registry_multiprocess_style_concurrency_serialized_by_flock(tmp_path):
    registry, _, _ = _registry_two(tmp_path)
    deployed = tmp_path / "active.joblib"
    def release(name):
        return ModelRegistry(registry.root).promote(name, deployed)
    with ThreadPoolExecutor(max_workers=8) as worker:
        outcomes = list(worker.map(release, ["baseline", "challenger"] * 6))
    assert len(outcomes) == 12
    assert registry.verify_active(deployed)["consistent"]
    assert len(registry.status()["history"]) == 12
    assert not registry.journal.exists()


def test_cli_production_blocks_insecure_release_and_verifies_active(tmp_path, monkeypatch):
    registry, _, _ = _registry_two(tmp_path)
    deployed = tmp_path / "live.joblib"
    args = [
        "model-registry", "promote", "--name", "baseline",
        "--root", str(registry.root), "--active", str(deployed),
    ]
    monkeypatch.setenv("NETWORKPULSE_DEPLOYMENT", "production")
    with pytest.raises(SystemExit):
        main(args)
    assert not deployed.exists()
    monkeypatch.setenv("NETWORKPULSE_DEPLOYMENT", "development")
    assert main(args) == 0
    assert main([
        "model-registry", "verify-active", "--root", str(registry.root),
        "--active", str(deployed)
    ]) == 0


def test_interrupted_release_reconciliation_never_installs_unapproved_bytes(tmp_path):
    registry, first, second = _registry_two(tmp_path)
    deployed = tmp_path / "live.joblib"
    registry.promote("baseline", deployed)
    import shutil
    shutil.copyfile(first, registry.rollback_copy)
    shutil.copyfile(second, deployed)  # simulate process dying after os.replace
    pending = {
        "previous": "baseline", "target": "challenger",
        "destination": str(deployed.resolve()),
        "target_sha256": sha256(second), "previous_sha256": sha256(first),
    }
    registry.journal.write_text(json.dumps(pending))
    with pytest.raises(RuntimeError, match="journal"):
        registry.verify_active(deployed)
    with pytest.raises(ValueError, match="approval"):
        registry.recover_interrupted(
            deployed, expected_target_sha256=sha256(second))
    with pytest.raises(ValueError, match="approval"):
        registry.recover_interrupted(
            deployed, expected_target_sha256="0"*64, confirm=True)
    result = registry.recover_interrupted(
        deployed, expected_target_sha256=sha256(second), confirm=True,
    )
    assert result["result"] == "previous_release_restored"
    assert sha256(deployed) == sha256(first)
    assert registry.verify_active(deployed)["active"] == "baseline"
    assert not registry.journal.exists()

    registry.promote("challenger", deployed)
    registry.journal.write_text(json.dumps(pending))
    done = registry.recover_interrupted(
        deployed, expected_target_sha256=sha256(second), confirm=True,
    )
    assert done["result"] == "committed_release_verified"
    assert registry.verify_active(deployed)["active"] == "challenger"


def test_offline_signed_approval_command_is_verifiable(tmp_path, trusted_signer):
    import subprocess
    import sys
    sign, trust, _ = trusted_signer
    # Ephemeral CLI signing key is intentionally never part of the repository.
    private = Ed25519PrivateKey.generate()
    trusted = json.loads(trust.read_text())
    trusted["keys"][0]["ed25519_public_key_base64"] = base64.b64encode(
        private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    trust.write_text(json.dumps(trusted))
    key_file = tmp_path / "offline.pem"
    key_file.write_bytes(private.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption(),
    ))
    os.chmod(key_file, 0o600)
    payload = tmp_path / "reviewed.json"
    payload.write_text(json.dumps(_payload("f"*64)))
    envelope = tmp_path / "signed.json"
    command = [
        sys.executable, "tools/sign_release_approval.py",
        "--payload", str(payload), "--private-key", str(key_file),
        "--key-id", "ci-security-approver", "--output", str(envelope),
    ]
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    assert '"signed": true' in completed.stdout
    assert verify_signed_approval(envelope, trust)["signature_verified"]
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.run(command, check=True, capture_output=True, text=True)
