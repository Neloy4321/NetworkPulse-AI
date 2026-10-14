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


def test_production_app_disables_documentation_at_source(monkeypatch, app_settings, tmp_path):
    """Public gateway restrictions alone must not protect Swagger/OpenAPI."""
    from fastapi.testclient import TestClient

    from networkpulse.model_registry import sha256
    from networkpulse.detector import Detector

    # This test isolates the access-control behavior. A fixture's source
    # string is *not* independent-site or artifact-provenance evidence.
    test_model = Detector.load(app_settings.model_path)
    test_model.metadata["source"] = "access_control_test_fixture"
    target = tmp_path / "isolated-security-control-test.joblib"
    test_model.save(target)

    class FakeRedis:
        def ping(self):
            return True

        def close(self):
            pass

    monkeypatch.setattr("redis.Redis.from_url", lambda *args, **kwargs: FakeRedis())
    config = replace(
        app_settings, deployment_mode="production", auth_mode="oidc",
        security_redis_url="redis://isolated", browser_oidc_enabled=True,
        model_path=target, model_sha256=sha256(target),
        oidc_issuer="https://idp.example.test", oidc_audience="networkpulse-api",
        oidc_jwks_url="https://idp.example.test/keys",
        oidc_auth_url="https://idp.example.test/auth",
        oidc_token_url="https://idp.example.test/token",
        oidc_client_id="networkpulse-browser",
        public_origin="https://soc.example.test",
    )
    # Production now requires a registry approved active release, not only
    # a checksum pin; this is test-only registry state, not site approval.
    from networkpulse.model_registry import ModelRegistry
    registry = ModelRegistry(tmp_path / "registry")
    registry.register("access-control-fixture", target)
    deployed = tmp_path / "active-security-fixture.joblib"
    registry.promote("access-control-fixture", deployed)
    config = replace(config, model_path=deployed, model_sha256=sha256(deployed))
    monkeypatch.setenv("NETWORKPULSE_MODEL_REGISTRY_ROOT", str(registry.root))
    with TestClient(create_app(config), base_url="https://soc.example.test") as client:
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(path).status_code == 404


def test_local_development_keeps_documentation(client):
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200


def test_production_rejects_synthetic_model_even_if_sha_matches(monkeypatch, app_settings):
    """A checksum does not make a seeded demo safe to serve in production."""
    from networkpulse.model_registry import sha256

    class FakeRedis:
        def ping(self):
            return True

        def close(self):
            pass

    monkeypatch.setattr("redis.Redis.from_url", lambda *a, **k: FakeRedis())
    settings = replace(
        app_settings, deployment_mode="production", auth_mode="oidc",
        security_redis_url="redis://private", browser_oidc_enabled=True,
        model_sha256=sha256(app_settings.model_path),
        oidc_issuer="https://issuer.example.test", oidc_audience="api",
        oidc_jwks_url="https://issuer.example.test/jwks",
        oidc_auth_url="https://issuer.example.test/auth",
        oidc_token_url="https://issuer.example.test/token",
        oidc_client_id="public-client", public_origin="https://soc.example.test",
    )
    with pytest.raises(ValueError, match="synthetic/demo"):
        create_app(settings)


def test_production_urls_disallow_insecure_redirects_and_embedded_credentials(app_settings):
    from networkpulse.security.deployment import validate_production_urls
    valid = replace(
        app_settings, oidc_issuer="https://issuer.example.test/realm",
        oidc_jwks_url="https://issuer.example.test/jwks",
        oidc_auth_url="https://issuer.example.test/authorize",
        oidc_token_url="https://issuer.example.test/token",
        public_origin="https://soc.example.test",
    )
    validate_production_urls(valid)
    with pytest.raises(ValueError, match="HTTPS"):
        validate_production_urls(replace(valid, oidc_token_url="http://idp.local/token"))
    with pytest.raises(ValueError, match="HTTPS"):
        validate_production_urls(replace(valid, oidc_jwks_url="https://user:pass@issuer.test/jwks"))
    with pytest.raises(ValueError, match="HTTPS"):
        validate_production_urls(replace(valid, public_origin="https://soc.example.test/redirect"))
    with pytest.raises(ValueError, match="HTTPS"):
        validate_production_urls(replace(valid, oidc_issuer="https://issuer.example.test/realm#fragment"))
