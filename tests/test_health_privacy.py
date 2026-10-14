"""Public health probes do not reveal filesystem training provenance."""
from dataclasses import replace
from fastapi.testclient import TestClient
from fastapi import HTTPException

from networkpulse.api import create_app


def test_unauthenticated_health_does_not_leak_training_paths(client):
    response = client.get("/health/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}
    assert "source" not in response.text
    assert "model_path" not in response.text


def test_oidc_mode_health_is_minimal_without_bearer(monkeypatch, app_settings):
    class MockVerifier:
        def __init__(self, *a, **kw):
            pass

        def verify(self, token):
            raise HTTPException(401, detail="invalid test token")

    monkeypatch.setattr("networkpulse.api.TokenVerifier", MockVerifier)
    settings = replace(
        app_settings, auth_mode="oidc", oidc_issuer="https://issuer.test",
        oidc_jwks_url="https://issuer.test/jwks", oidc_audience="np-api"
    )
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/v1/model").status_code == 401
        response = client.get("/health/ready")
        assert response.status_code == 200
        assert response.json() == {"status": "ready"}
