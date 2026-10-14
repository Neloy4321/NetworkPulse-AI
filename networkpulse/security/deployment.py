"""Fail-closed structural checks for externally supplied production OIDC URLs.

This validates URL shape, NOT IdP identity, DNS control, certs or actual
end-to-end PKCE login; those are separate site acceptance checks.
"""
from __future__ import annotations

from urllib.parse import urlsplit


def validate_production_urls(settings) -> None:
    fields = {
        "OIDC issuer": settings.oidc_issuer,
        "OIDC JWKS": settings.oidc_jwks_url,
        "OIDC authorize": settings.oidc_auth_url,
        "OIDC token": settings.oidc_token_url,
        "Public origin": settings.public_origin,
    }
    for name, address in fields.items():
        try:
            parsed = urlsplit(address)
            valid = (parsed.scheme == "https" and bool(parsed.hostname) and
                     parsed.username is None and parsed.password is None and
                     parsed.port != 0 and not parsed.fragment)
            if name == "Public origin":
                valid = valid and parsed.path in ("", "/") and not parsed.query
            else:
                # OIDC endpoints/issuer may have paths; prohibit URL query
                # strings because these are permanent configuration values.
                valid = valid and not parsed.query
        except (ValueError, TypeError, AttributeError):
            valid = False
        if not valid:
            raise ValueError(f"Production {name} requires an HTTPS URL without credentials/query/fragment")
