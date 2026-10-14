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
