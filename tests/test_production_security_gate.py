"""Fail-closed direct create_app constructor in production as well as env parsing."""
from dataclasses import replace

import pytest

from networkpulse.api import create_app


def test_production_rejects_missing_browser_ssr_and_model_hash(app_settings):
    base = replace(
        app_settings, deployment_mode="production",
        auth_mode="oidc", security_redis_url="redis://fake",
        oidc_issuer="https://issuer.test", oidc_audience="api",
        oidc_jwks_url="https://issuer.test/jwks",
    )
    with pytest.raises(ValueError, match="browser OIDC login"):
        create_app(base)
    with pytest.raises(ValueError, match="checksum-pinned"):
        create_app(replace(base, browser_oidc_enabled=True))


def test_manual_settings_cannot_enable_browser_login_in_local_mode(app_settings):
    with pytest.raises(ValueError, match="requires OIDC"):
        create_app(replace(app_settings, browser_oidc_enabled=True))


def test_production_app_disables_documentation_at_source(monkeypatch, app_settings):
    """Public gateway restrictions alone must not protect Swagger/OpenAPI."""
    from fastapi.testclient import TestClient

    from networkpulse.model_registry import sha256

    class FakeRedis:
        def ping(self):
            return True

        def close(self):
            pass

    monkeypatch.setattr("redis.Redis.from_url", lambda *args, **kwargs: FakeRedis())
    config = replace(
        app_settings, deployment_mode="production", auth_mode="oidc",
        security_redis_url="redis://isolated", browser_oidc_enabled=True,
        model_sha256=sha256(app_settings.model_path),
        oidc_issuer="https://idp.example.test", oidc_audience="networkpulse-api",
        oidc_jwks_url="https://idp.example.test/keys",
        oidc_auth_url="https://idp.example.test/auth",
        oidc_token_url="https://idp.example.test/token",
        oidc_client_id="networkpulse-browser",
        public_origin="https://soc.example.test",
    )
    with TestClient(create_app(config), base_url="https://soc.example.test") as client:
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(path).status_code == 404


def test_local_development_keeps_documentation(client):
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200
