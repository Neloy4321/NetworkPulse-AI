"""Stage A isolated non-ML staging contract: no model promotion or auth bypass."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from networkpulse.infra_staging import (
    DATABASE_NAME, STAGING_MODE, InfraStagingSettings, create_app,
    create_production_like_staging_app,
)
from networkpulse.security.oidc import Principal


class FakeVerifier:
    """TEST-ONLY principal; actual factory instantiates RS256 TokenVerifier."""

    def verify(self, token: str) -> Principal:
        roles = {"fixture-viewer": "viewer", "fixture-analyst": "analyst",
                 "fixture-admin": "admin"}
        if token not in roles:
            raise HTTPException(401, detail="invalid mock OIDC")
        return Principal(subject="synthetic-test-only", role=roles[token])


class Checks:
    def __init__(self):
        self.postgres = True
        self.redis = True
        self.closed = False

    def postgres_ready(self):
        if isinstance(self.postgres, Exception):
            raise self.postgres
        return self.postgres

    def redis_ready(self):
        if isinstance(self.redis, Exception):
            raise self.redis
        return self.redis

    def close(self):
        self.closed = True


def settings():
    return InfraStagingSettings(
        db_host="db", db_password="private-unit-db-secret-1234",
        redis_host="redis", redis_password="private-unit-redis-secret-1234",
        oidc_issuer="https://idp.example.test/issuer",
        oidc_jwks_url="https://idp.example.test/jwks",
        oidc_audience="nonml-staging",
        oidc_role_claim="networkpulse_role",
    )


def client(checks: Checks):
    return TestClient(create_app(settings(), verifier=FakeVerifier(), checks=checks))


def test_status_and_canonical_staging_scope_cannot_impersonate_ids():
    assert STAGING_MODE == "non_ml_infrastructure_only"
    assert DATABASE_NAME == "networkpulse_staging_infra"
    checks = Checks()
    with client(checks) as api:
        assert api.get("/health/live").json() == {
            "status": "live", "mode": STAGING_MODE
        }
        response = api.get("/health/ready")
        assert response.status_code == 200
        result = response.json()
        assert result["model_loaded"] is False
        assert result["ml_acceptance_claimed"] is False
        assert result["dependencies"] == {"postgres": "ready", "redis": "ready"}
        assert "Cache-Control" in response.headers
        assert response.headers["X-Frame-Options"] == "DENY"
        assert api.get("/api/v1/ingest").status_code == 404
        assert api.post("/api/v1/ingest", json={}).status_code == 404
        assert api.get("/api/v2/score").status_code == 404
        assert api.get("/docs").status_code == 404
        assert api.get("/openapi.json").status_code == 404
    assert checks.closed


@pytest.mark.parametrize("dependency", ["postgres", "redis"])
def test_unavailable_or_failed_service_is_not_healthy(dependency):
    checks = Checks()
    setattr(checks, dependency, False)
    with client(checks) as api:
        response = api.get("/health/ready")
        assert response.status_code == 503
        assert "private-unit-db-secret" not in response.text
        assert api.get("/health/live").status_code == 200
        metric = api.get("/internal/metrics")
        assert metric.status_code == 200
        assert ('dependency="' + dependency + '"} 0.0') in metric.text


def test_internal_dependency_exception_is_redacted():
    checks = Checks()
    checks.postgres = RuntimeError("private-test-db-password-should-be-hidden")
    with client(checks) as api:
        response = api.get("/health/ready")
        assert response.status_code == 503
        assert "private-test-db-password" not in response.text


def test_no_public_authenticated_business_operation_without_real_token():
    with client(Checks()) as api:
        for endpoint in ("viewer", "analyst", "admin"):
            assert api.get("/api/staging/" + endpoint).status_code == 401
            assert api.get(
                "/api/staging/" + endpoint,
                headers={"Authorization": "Bearer invalid-fixture"},
            ).status_code == 401
        assert api.post("/api/staging/admin", json={}).status_code == 405


@pytest.mark.parametrize("role,permissions", [
    ("viewer", (200, 403, 403)),
    ("analyst", (200, 200, 403)),
    ("admin", (200, 200, 200)),
])
def test_oidc_viewer_analyst_admin_rbac_matrix(role, permissions):
    with client(Checks()) as api:
        for endpoint, expected in zip(("viewer", "analyst", "admin"), permissions):
            response = api.get(
                "/api/staging/" + endpoint,
                headers={"Authorization": "Bearer fixture-" + role},
            )
            assert response.status_code == expected
            if expected == 200:
                assert response.json()["model_loaded"] is False
                assert response.json()["mode"] == STAGING_MODE


def test_explicit_mode_and_operator_secrets_mandatory(monkeypatch):
    monkeypatch.delenv("NETWORKPULSE_STAGING_MODE", raising=False)
    with pytest.raises(ValueError, match="isolated"):
        create_production_like_staging_app()
    monkeypatch.setenv("NETWORKPULSE_STAGING_MODE", STAGING_MODE)
    monkeypatch.setenv("NETWORKPULSE_STAGING_DB_NAME", "networkpulse")
    with pytest.raises(ValueError, match="non-staging"):
        create_production_like_staging_app()
    monkeypatch.setenv("NETWORKPULSE_STAGING_DB_NAME", DATABASE_NAME)
    monkeypatch.setenv("NETWORKPULSE_STAGING_OIDC_AUDIENCE", "nonml-test")
    with pytest.raises(ValueError, match="STAGING_DB_PASSWORD"):
        create_production_like_staging_app()


def test_invalid_oidc_and_secret_rejected_without_credentials_in_logs(monkeypatch):
    env = {
        "NETWORKPULSE_STAGING_MODE": STAGING_MODE,
        "NETWORKPULSE_STAGING_DB_PASSWORD": "unit-test-db-staging-password-123",
        "NETWORKPULSE_STAGING_REDIS_PASSWORD": "unit-test-redis-staging-password-123",
        "NETWORKPULSE_STAGING_OIDC_ISSUER": "http://insecure-idp.test",
        "NETWORKPULSE_STAGING_OIDC_JWKS_URL": "https://idp.example.test/jwks",
        "NETWORKPULSE_STAGING_OIDC_AUDIENCE": "nonml-staging",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(ValueError, match="trusted HTTPS"):
        create_production_like_staging_app()
    monkeypatch.setenv("NETWORKPULSE_STAGING_OIDC_ISSUER", "https://idp.example.test")
    monkeypatch.setenv("NETWORKPULSE_STAGING_REDIS_PASSWORD", "changeme123456789012345")
    with pytest.raises(ValueError, match="STAGING_REDIS_PASSWORD"):
        create_production_like_staging_app()


def test_static_docker_contract_no_models_or_public_metrics():
    root = Path(__file__).resolve().parents[1]
    dockerfile = (root / "deploy/Dockerfile.infra-staging").read_text()
    compose = (root / "deploy/compose.infra-staging.yml").read_text()
    gateway = (root / "infra/Caddyfile.infra-staging").read_text()
    assert "networkpulse.infra_staging:create_production_like_staging_app" in dockerfile
    assert "Detector.load" not in dockerfile
    assert "data/model.joblib" not in dockerfile
    assert "non_ml_infrastructure_only" in compose
    assert "networkpulse_staging_infra" in compose
    assert "compose.yaml" not in compose.split("services:")[1]
    assert "127.0.0.1:8000:8000" not in compose
    assert "ports:" not in compose.split("  prometheus:")[1]
    assert "ports:" not in compose.split("  api:")[1].split("  caddy:")[0]
    assert "path /internal/*" in gateway
    assert "respond @private 404" in gateway
    assert "reverse_proxy api:8000" in gateway
