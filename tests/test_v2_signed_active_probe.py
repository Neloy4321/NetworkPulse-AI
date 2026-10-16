"""Synthetic HTTP fixtures ONLY; these are NOT real deployment evidence."""
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest

from networkpulse.evaluation.v2_signed_active_probe import probe
from networkpulse.feature_contract_v2 import FlowV2, V2_FEATURE_CONTRACT


def flow():
    return FlowV2(
        timestamp=datetime(2026,10,16,tzinfo=timezone.utc),
        source="zeek", src_ip="192.0.2.1", src_port=50000,
        dst_ip="198.51.100.4", dst_port=443, proto="tcp",
        duration=None, orig_bytes=None, resp_bytes=100,
    )


def fake_runtime():
    prediction = {
        "anomalous": False, "probability": 0.01,
        "threshold": 0.2, "feature_contract": V2_FEATURE_CONTRACT,
    }
    return SimpleNamespace(
        artifact_sha256="a"*64,
        score=lambda rows:[prediction for _ in rows],
    )


@pytest.mark.parametrize("url", [
    "http://example.com", "https://user:pass@example.com",
    "https://example.com/path", "https://example.com/?redirect=evil",
    "https://example.com/#fragment",
])
def test_real_tls_origin_only_and_no_sensitive_urls(url):
    with pytest.raises(ValueError,match="Real HTTPS"):
        probe(url, "private-token", fake_runtime(), [flow()])


def test_labels_never_sent_to_remote_production_endpoint():
    labeled = flow().model_copy(update={"label":"anomaly"})
    with pytest.raises(ValueError,match="ground truth"):
        probe("https://example.com","fake-test-token",fake_runtime(),[labeled])


def test_mismatched_remote_signed_artifact_fail_closed(monkeypatch):
    original = httpx.Client

    def transport(request):
        if request.url.path == "/health/ready":
            return httpx.Response(200,json={
                "status":"ready", "signed_artifact_sha256":"b"*64,
                "feature_contract":V2_FEATURE_CONTRACT,
                "release_signature_verified":True,
            })
        return httpx.Response(500)

    def fake_client(*,timeout,follow_redirects,verify,trust_env):
        assert verify is True and follow_redirects is False and trust_env is False
        return original(transport=httpx.MockTransport(transport))

    monkeypatch.setattr(httpx,"Client",fake_client)
    with pytest.raises(ValueError, match="host/model signing"):
        probe("https://example.com","dummy-token",fake_runtime(),[flow()])


def test_mocked_http_parity_is_not_real_independent_site_proof(monkeypatch):
    original=httpx.Client
    model=fake_runtime()

    def handler(request):
        if request.url.path == "/health/ready":
            return httpx.Response(200,json={
                "status":"ready", "signed_artifact_sha256":model.artifact_sha256,
                "feature_contract":V2_FEATURE_CONTRACT,
                "release_signature_verified":True,
            })
        assert request.headers["authorization"]=="Bearer dummy-test-only"
        assert "192.0.2.1" in request.content.decode()
        return httpx.Response(200,json={
            "artifact_sha256":model.artifact_sha256,
            "feature_contract":V2_FEATURE_CONTRACT,
            "scored":1, "predictions":model.score([flow()]),
        })

    monkeypatch.setattr(httpx,"Client",lambda **kwargs: original(
        transport=httpx.MockTransport(handler)
    ))
    result=probe("https://example.com","dummy-test-only",model,[flow()])
    assert result["sample_prediction_parity"] is True
    assert result["p0_operational_ml_acceptance"] == "NO_GO"
    assert result["independent_site_ground_truth_verified_by_this_probe"] is False
    assert result["signed_release_operator_evidence_is_externally_audited"] is False
    assert "example.com" not in str(result)


def test_remote_api_prediction_drift_causes_integrity_failure(monkeypatch):
    original=httpx.Client
    model=fake_runtime()

    def handler(request):
        if request.url.path.endswith("/ready"):
            return httpx.Response(200,json={
                "status":"ready", "signed_artifact_sha256":model.artifact_sha256,
                "feature_contract":V2_FEATURE_CONTRACT,
                "release_signature_verified":True,
            })
        return httpx.Response(200,json={
            "artifact_sha256":model.artifact_sha256,
            "feature_contract":V2_FEATURE_CONTRACT,
            "scored":1,"predictions":[{"anomalous":True}],
        })

    monkeypatch.setattr(httpx,"Client",lambda **kwargs: original(
        transport=httpx.MockTransport(handler)
    ))
    with pytest.raises(ValueError,match="different predictions"):
        probe("https://example.com","dummy",model,[flow()])
