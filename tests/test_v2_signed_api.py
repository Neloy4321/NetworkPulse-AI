"""Ephemeral CI signer+OIDC doubles, never real production deployment proof."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from networkpulse.v2_signed_api import (
    create_signed_v2_app, create_production_v2_app,
)
from networkpulse.v2_signed_runtime import V2SignedRuntime


class TestPrincipal:
    def require(self, role):
        if role != "analyst":
            raise PermissionError("role refused")


class TestVerifier:
    def verify(self, token):
        if token != "synthetic-fixture-only":
            raise ValueError("not a trusted OIDC token")
        return TestPrincipal()


def setup_synthetic(tmp_path: Path):
    from test_v2_signed_runtime import fixtures, event
    blob, meta, receipt, trust, sha = fixtures(tmp_path)
    signed = V2SignedRuntime.open(
        blob, meta, receipt, trust, expected_sha256=sha
    )
    return signed, event


def test_default_anonymous_access_denied_and_no_legacy_fallback(tmp_path: Path):
    signed, event = setup_synthetic(tmp_path)
    app = create_signed_v2_app(runtime=signed, verifier=TestVerifier())
    with TestClient(app) as client:
        assert client.get("/health/live").status_code == 200
        readiness = client.get("/health/ready").json()
        assert readiness["signed_artifact_sha256"] == signed.artifact_sha256
        assert "not external site truth" in readiness["warning"]
        assert client.post("/api/v2/score", json={"flows":[
            event(1).model_dump(mode="json")
        ]}).status_code == 401
        assert client.post(
            "/api/v2/score", headers={"Authorization":"Bearer wrong"},
            json={"flows":[event(1).model_dump(mode="json")]},
        ).status_code == 403
        assert client.post("/api/v1/ingest", json={}).status_code == 404


def test_oidc_gated_v2_scores_without_echoing_network_identifiers(tmp_path: Path):
    signed, event = setup_synthetic(tmp_path)
    app = create_signed_v2_app(runtime=signed, verifier=TestVerifier())
    flows = [event(2), event(9,missing=True)]
    with TestClient(app) as client:
        result = client.post(
            "/api/v2/score",
            headers={"Authorization":"Bearer synthetic-fixture-only"},
            json={"flows":[e.model_dump(mode="json") for e in flows]},
        )
        assert result.status_code == 200, result.text
        body = result.json()
        assert body["scored"] == 2
        assert body["predictions"] == signed.score(flows)
        assert "192.0.2" not in json.dumps(body)
        assert "198.51.100" not in json.dumps(body)
        assert "uid" not in json.dumps(body)


def test_no_signed_runtime_instance_is_rejected():
    with pytest.raises(ValueError, match="Signed V2 runtime"):
        create_signed_v2_app(runtime=None, verifier=TestVerifier())


def test_unconfigured_or_development_production_entrypoint_fails_closed(monkeypatch):
    monkeypatch.setenv("NETWORKPULSE_DEPLOYMENT_MODE", "development")
    with pytest.raises(ValueError, match="requires production OIDC"):
        create_production_v2_app()


def test_labeled_input_rejected_and_invalid_request_never_score(tmp_path: Path):
    signed, event = setup_synthetic(tmp_path)
    app = create_signed_v2_app(runtime=signed, verifier=TestVerifier())
    with TestClient(app) as client:
        labeled = event(5).model_copy(update={"label": "anomaly"})
        # Type validation accepts a label in FlowV2 schema, but scoring MUST reject.
        with pytest.raises(ValueError, match="training labels"):
            signed.score([labeled])
        # TestClient re-raises internal server exceptions by default; no prediction.
        with pytest.raises(ValueError, match="training labels"):
            client.post(
                "/api/v2/score",
                headers={"Authorization":"Bearer synthetic-fixture-only"},
                json={"flows":[labeled.model_dump(mode="json")]},
            )


def test_score_endpoint_has_bounded_requests_and_no_docs(tmp_path: Path):
    signed, event = setup_synthetic(tmp_path)
    with TestClient(create_signed_v2_app(runtime=signed, verifier=TestVerifier())) as c:
        assert c.get("/docs").status_code == 404
        assert c.get("/openapi.json").status_code == 404
        assert c.post(
            "/api/v2/score", headers={"Authorization":"Bearer synthetic-fixture-only"},
            json={"flows":[]},
        ).status_code == 422
        assert c.post(
            "/api/v2/score", headers={"Authorization":"Bearer synthetic-fixture-only"},
            json={"flows":[event(1).model_dump(mode="json")]*513},
        ).status_code == 422
