import json
import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from networkpulse.release_approval import canonical_bytes

from networkpulse.detector import train
from networkpulse.model_registry import ModelRegistry, sha256
from networkpulse.simulator import sample_flows


def test_registered_candidates_gate_on_uncertain_benign_fpr(tmp_path):
    model = train(sample_flows(1200, seed=41), seed=41, source="seeded_synthetic_demo")
    path = tmp_path / "artifact.joblib"
    model.save(path)
    registry = ModelRegistry(tmp_path / "registry")
    upper = model.metadata["metrics"]["fpr_wilson_upper_95_one_sided"]
    with pytest.raises(ValueError, match="uncertainty gate"):
        registry.register("strict", path, max_fpr_upper_95=max(.001, upper - .02))
    record = registry.register("passing", path, max_fpr_upper_95=min(1., upper + .02))
    assert record["gate"]["max_fpr_upper_95"] is not None
    with pytest.raises(ValueError, match="production requires"):
        registry.promote("passing", tmp_path/"live.joblib", production=True)
    receipt = tmp_path/"evidence.json"
    receipt.write_text(json.dumps({
        "candidate_sha256": record["sha256"],
        "independent_site_verified": True,
        "live_sensor_contract_verified": True,
        "training_test_leakage_audited": True,
        "approved_by": "Trusted operator",
        "evaluation": {"benign_count": 1000, "attack_count": 250,
                       "false_positives": 2},
    }))
    with pytest.raises(ValueError, match="synthetic"):
        registry.promote("passing", tmp_path/"live.joblib", production=True,
                         evidence_path=receipt)
    assert not (tmp_path/"live.joblib").exists()


def test_production_receipt_verification_fail_closed(tmp_path):
    model = train(sample_flows(1300, seed=42), seed=42, source="trusted_real_capture")
    model_path = tmp_path/"real.joblib"
    model.save(model_path)
    registry = ModelRegistry(tmp_path/"registry")
    record = registry.register("real-a", model_path)
    out = tmp_path/"production.joblib"
    path = tmp_path/"receipt.json"
    private = Ed25519PrivateKey.generate()
    trust = tmp_path / "trusted-review-signers.json"
    trust.write_text(json.dumps({
        "schema_version": 1,
        "keys": [{
            "key_id": "ci-independent-reviewer",
            "enabled": True,
            "ed25519_public_key_base64": base64.b64encode(
                private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            ).decode(),
        }],
    }))
    now = datetime.now(timezone.utc)
    receipt = {
        "issued_at_utc": (now - timedelta(minutes=3)).isoformat().replace("+00:00", "Z"),
        "expires_at_utc": (now + timedelta(days=2)).isoformat().replace("+00:00", "Z"),
        "candidate_sha256": record["sha256"],
        "previous_active": None,
        "operation": "promote",
        "change_id": "ci-production-review-001",
        "independent_site_verified": False,
        "live_sensor_contract_verified": True,
        "training_test_leakage_audited": True,
        "approved_by": "SOC lead",
        "evaluation": {"benign_count": 1000, "attack_count": 50,
                       "false_positives": 3},
    }
    def sign_current():
        envelope = {
            "schema_version": 1, "key_id": "ci-independent-reviewer",
            "payload": receipt,
            "signature": base64.b64encode(private.sign(canonical_bytes(receipt))).decode(),
        }
        path.write_text(json.dumps(envelope))

    sign_current()
    with pytest.raises(ValueError, match="site"):
        registry.promote("real-a", out, production=True,
                         evidence_path=path, trust_store=trust)
    receipt["independent_site_verified"] = True
    receipt["candidate_sha256"] = "0" * 64
    sign_current()
    with pytest.raises(ValueError, match="checksum"):
        registry.promote("real-a", out, production=True,
                         evidence_path=path, trust_store=trust)
    receipt["candidate_sha256"] = record["sha256"]
    receipt["evaluation"]["false_positives"] = 350
    sign_current()
    with pytest.raises(ValueError, match="budget exceeded"):
        registry.promote("real-a", out, production=True,
                         evidence_path=path, trust_store=trust)
    receipt["evaluation"]["false_positives"] = 1
    sign_current()
    result = registry.promote("real-a", out, production=True,
                         evidence_path=path, trust_store=trust)
    assert result["production_policy"] is True
    assert sha256(out) == record["sha256"]
    assert registry.status()["history"][-1]["validation_receipt"]["signature_verified"] is True
    assert registry.verify_active(out)["consistent"] is True
