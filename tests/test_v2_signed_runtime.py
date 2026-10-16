"""Synthetic-only signer/flow fixtures; no real network operator approval."""
import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import joblib
import numpy as np
import pytest
import sklearn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer

from networkpulse.feature_contract_v2 import (
    V2_FEATURE_CONTRACT, FlowV2, features_v2,
)
from networkpulse.release_approval import canonical_bytes
from networkpulse.v2_signed_runtime import (
    V2SignedRuntime, assess_signed_release_quality, wilson_lower_bound,
)


def event(i: int, *, missing: bool = False) -> FlowV2:
    return FlowV2(
        timestamp=datetime(2026, 9, 5, tzinfo=timezone.utc),
        source="zeek", src_ip="192.0.2.1", dst_ip="198.51.100.2",
        src_port=21000+i, dst_port=443, proto="tcp",
        duration=None if missing else float(i + 1),
        orig_bytes=None if missing else 120 + i,
        resp_bytes=20 + i, orig_pkts=2+i, resp_pkts=None if missing else 10+i,
        conn_state="s0",
    )


def quality_payload(sha: str) -> dict:
    now = datetime.now(timezone.utc)
    def stamp(t):
        return t.isoformat(timespec="seconds").replace("+00:00", "Z")
    return {
        "candidate_sha256": sha,
        "independent_site_verified": True,
        "live_sensor_contract_verified": True,
        "training_test_leakage_audited": True,
        "approved_by": "Synthetic CI Fixture Operator — NOT A REAL APPROVAL",
        "evaluation": {
            "benign_count": 800,
            "attack_count": 400,
            "false_positives": 8,
            "true_positives": 392,
            "feature_contract": V2_FEATURE_CONTRACT,
            "dataset_kind": "independent_operator_site",
            "labels_independently_reviewed": True,
            "deployed_sensor_parity_checked": True,
            "distinct_capture_days": 3,
        },
        "issued_at_utc": stamp(now - timedelta(minutes=1)),
        "expires_at_utc": stamp(now + timedelta(hours=6)),
        "previous_active": None,
        "operation": "promote",
        "change_id": "synthetic-ci-no-real-approval",
    }


def fixtures(tmp_path: Path, payload_update=None):
    training = [event(i, missing=(i % 4 == 0)) for i in range(30)]
    vectorizer = DictVectorizer(sparse=False)
    x = vectorizer.fit_transform([features_v2(e) for e in training])
    y = np.array([0]*15+[1]*15)
    model = RandomForestClassifier(n_estimators=12, max_depth=3, random_state=42).fit(x,y)
    meta = {
        "status": "mixed_exposed_source_v2_research_model_frozen",
        "artifact_sha256": None,
        "production_signed": False,
        "independent_test_performed": False,
        "protocol": {"feature_contract": V2_FEATURE_CONTRACT, "threshold": 0.5},
        "protocol_sha256": "f" * 64,
    }
    blob = {
        "schema_version": 2,
        "research_only": True,
        "production_approved": False,
        "feature_contract": V2_FEATURE_CONTRACT,
        "protocol_sha256": meta["protocol_sha256"],
        "scikit_learn_version": sklearn.__version__,
        "fixed_cutoff": 0.5,
        "vectorizer": vectorizer,
        "estimator": model,
    }
    path = tmp_path/"model.joblib"
    joblib.dump(blob,path)
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    meta["artifact_sha256"] = sha
    manifest = tmp_path/"manifest.json"
    manifest.write_text(json.dumps(meta))
    payload = quality_payload(sha)
    if payload_update:
        payload_update(payload)
    private = Ed25519PrivateKey.generate()
    key_data = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw
    )
    trust = tmp_path/"out-of-band-test-trust.json"
    trust.write_text(json.dumps({
        "schema_version": 1,
        "keys": [{
            "key_id": "synthetic-unit-test-key",
            "enabled": True,
            "ed25519_public_key_base64": base64.b64encode(key_data).decode(),
        }],
    }))
    receipt = tmp_path/"synthetic-signed-receipt.json"
    receipt.write_text(json.dumps({
        "schema_version": 1,
        "key_id": "synthetic-unit-test-key",
        "payload": payload,
        "signature": base64.b64encode(
            private.sign(canonical_bytes(payload))
        ).decode(),
    }))
    return path, manifest, receipt, trust, sha


def test_synthetic_signed_model_runtime_parity_without_retraining(tmp_path: Path):
    path, manifest, receipt, trust, sha = fixtures(tmp_path)
    runtime = V2SignedRuntime.open(
        path, manifest, receipt, trust, expected_sha256=sha
    )
    events = [event(7), event(4,missing=True)]
    scored = runtime.score(events)
    original = joblib.load(path)
    expected = original["estimator"].predict_proba(
        original["vectorizer"].transform([features_v2(e) for e in events])
    )[:, 1]
    assert [r["probability"] for r in scored] == [
        round(float(p), 6) for p in expected
    ]
    assert all(r["feature_contract"] == V2_FEATURE_CONTRACT for r in scored)
    assert runtime.artifact_sha256 == sha
    assert runtime.release_quality["verified_numeric_gate"] is True
    assert runtime.release_quality["human_claims_require_external_audit"] is True


def test_recall_lower_bound_enforced_not_just_fpr():
    payload = quality_payload("a"*64)
    payload["evaluation"]["true_positives"] = 310
    with pytest.raises(ValueError, match="Recall Wilson lower"):
        assess_signed_release_quality(payload, model_sha256="a"*64)
    assert wilson_lower_bound(392, 400) >= .8


def test_false_positives_enforced():
    payload = quality_payload("a"*64)
    payload["evaluation"]["false_positives"] = 70
    with pytest.raises(ValueError, match="FPR Wilson upper"):
        assess_signed_release_quality(payload, model_sha256="a"*64)


@pytest.mark.parametrize("field", [
    "independent_site_verified", "live_sensor_contract_verified",
    "training_test_leakage_audited",
])
def test_missing_independent_site_evidence_fails_even_with_high_metrics(field):
    payload = quality_payload("b"*64)
    payload[field] = False
    with pytest.raises(ValueError, match="site/sensor/leakage"):
        assess_signed_release_quality(payload, model_sha256="b"*64)


def test_wrong_evidence_claim_or_insufficient_support_fails():
    payload = quality_payload("a"*64)
    payload["evaluation"]["dataset_kind"] = "controlled_lab"
    with pytest.raises(ValueError, match="site/ground-truth"):
        assess_signed_release_quality(payload, model_sha256="a"*64)
    payload = quality_payload("a"*64)
    payload["evaluation"]["attack_count"] = 16
    with pytest.raises(ValueError, match="support"):
        assess_signed_release_quality(payload, model_sha256="a"*64)
    payload = quality_payload("a"*64)
    payload["evaluation"]["distinct_capture_days"] = 1
    with pytest.raises(ValueError, match="Multiple"):
        assess_signed_release_quality(payload, model_sha256="a"*64)


def test_signed_receipt_tamper_or_untrusted_key_rejected_before_pickle(tmp_path: Path):
    path, meta, receipt, trust, sha = fixtures(tmp_path)
    envelope = json.loads(receipt.read_text())
    envelope["payload"]["evaluation"]["true_positives"] = 399
    receipt.write_text(json.dumps(envelope))
    with pytest.raises(ValueError, match="signature"):
        V2SignedRuntime.open(path, meta, receipt, trust, expected_sha256=sha)
    receipt.unlink()
    with pytest.raises(ValueError, match="unavailable/invalid"):
        V2SignedRuntime.open(path, meta, receipt, trust, expected_sha256=sha)


def test_model_tamper_rejected_before_deserialization(tmp_path: Path):
    path, meta, receipt, trust, sha = fixtures(tmp_path)
    with path.open("ab") as f:
        f.write(b"evil-append")
    with pytest.raises(ValueError, match="differ from approved"):
        V2SignedRuntime.open(path, meta, receipt, trust, expected_sha256=sha)


def test_no_signature_no_release_and_no_unreviewed_untrusted_bytes(tmp_path: Path):
    path, meta, receipt, trust, sha = fixtures(tmp_path)
    with pytest.raises(ValueError, match="out-of-band"):
        V2SignedRuntime.open(path, meta, receipt, trust, expected_sha256="unknown")
    missing = tmp_path/"no-receipt.json"
    with pytest.raises(ValueError, match="unavailable/invalid"):
        V2SignedRuntime.open(path, meta, missing, trust, expected_sha256=sha)


def test_non_v2_or_labeled_inference_forbidden(tmp_path: Path):
    path, meta, receipt, trust, sha = fixtures(tmp_path)
    active = V2SignedRuntime.open(path, meta, receipt, trust, expected_sha256=sha)
    with pytest.raises(TypeError, match="FlowV2"):
        active.score([{"src_port": 4}])
    with pytest.raises(ValueError, match="cannot be given training labels"):
        active.score([event(4).model_copy(update={"label": "anomaly"})])
    with pytest.raises(ValueError, match="Bounded"):
        active.score([event(4)]*513)
