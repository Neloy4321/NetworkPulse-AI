import json

import pytest

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
    receipt = {
        "candidate_sha256": record["sha256"],
        "independent_site_verified": False,
        "live_sensor_contract_verified": True,
        "training_test_leakage_audited": True,
        "approved_by": "SOC lead",
        "evaluation": {"benign_count": 1000, "attack_count": 50,
                       "false_positives": 3},
    }
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="site"):
        registry.promote("real-a", out, production=True, evidence_path=path)
    receipt["independent_site_verified"] = True
    receipt["candidate_sha256"] = "0" * 64
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="checksum"):
        registry.promote("real-a", out, production=True, evidence_path=path)
    receipt["candidate_sha256"] = record["sha256"]
    receipt["evaluation"]["false_positives"] = 350
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="budget exceeded"):
        registry.promote("real-a", out, production=True, evidence_path=path)
    receipt["evaluation"]["false_positives"] = 1
    path.write_text(json.dumps(receipt))
    result = registry.promote("real-a", out, production=True, evidence_path=path)
    assert result["production_policy"] is True
    assert sha256(out) == record["sha256"]
    assert registry.status()["history"][-1]["validation_receipt"]["authenticity_not_cryptographically_verified"]
