from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from networkpulse.api import create_app
from networkpulse.config import Settings
from networkpulse.detector import train
from networkpulse.migrations import upgrade_database
from networkpulse.simulator import sample_flows


@pytest.fixture(scope="session")
def trained_detector():
    return train(sample_flows(310, seed=15), seed=15)


@pytest.fixture
def app_settings(tmp_path: Path, trained_detector):
    model_file = tmp_path / "model.joblib"
    trained_detector.save(model_file)
    settings = Settings(
        database_url="sqlite:///" + str(tmp_path / "networkpulse.db"),
        model_path=model_file,
        api_key="local-test-api-key-strong-123",
    )
    upgrade_database(settings.database_url)
    return settings


@pytest.fixture
def client(app_settings):
    with TestClient(create_app(app_settings)) as api:
        yield api


@pytest.fixture
def samples():
    return sample_flows(310, seed=15)

@pytest.fixture
def ci_release_signer(tmp_path):
    """Ephemeral unit-test signature, never actual independent site approval."""
    import base64
    import json
    from datetime import datetime, timedelta, timezone
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from networkpulse.release_approval import canonical_bytes

    key = Ed25519PrivateKey.generate()
    trust = tmp_path / "ci-only-trust-store.json"
    trust.write_text(json.dumps({
        "schema_version": 1, "keys": [{
            "key_id": "ci-test-signer", "enabled": True,
            "ed25519_public_key_base64": base64.b64encode(
                key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            ).decode(),
        }],
    }))

    def sign(candidate_sha, *, change_id="ci-only-runtime-preflight"):
        now = datetime.now(timezone.utc)
        payload = {
            "candidate_sha256": candidate_sha, "previous_active": None,
            "operation": "promote", "change_id": change_id,
            "independent_site_verified": True,
            "live_sensor_contract_verified": True,
            "training_test_leakage_audited": True,
            "approved_by": "CI TEST FIXTURE (no real independent validation)",
            "evaluation": {"benign_count": 400, "attack_count": 40,
                           "false_positives": 1},
            "issued_at_utc": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
            "expires_at_utc": (now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        }
        envelope = {
            "schema_version": 1, "key_id": "ci-test-signer",
            "payload": payload,
            "signature": base64.b64encode(key.sign(canonical_bytes(payload))).decode(),
        }
        approval = tmp_path / (change_id + ".json")
        approval.write_text(json.dumps(envelope))
        return approval, trust

    return sign
