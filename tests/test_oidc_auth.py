from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from networkpulse.security.oidc import Principal, TokenVerifier


def test_roles_and_explicit_permission_denial():
    Principal("u", "admin").require("admin")
    Principal("u", "analyst").require("viewer")
    with pytest.raises(HTTPException) as exc:
        Principal("u", "viewer").require("analyst")
    assert exc.value.status_code == 403


def test_jwt_verified_signature_expiry_and_role_mapping():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key()
    verifier = TokenVerifier("https://issuer.test", "networkpulse-api", "https://issuer.test/jwks")
    verifier.jwks.get_signing_key_from_jwt = lambda token: type("Key", (), {"key": public})()
    now = datetime.now(timezone.utc)
    claims = {"sub": "researcher-123", "aud": "networkpulse-api", "iss": "https://issuer.test", "iat": int(now.timestamp()), "exp": int((now+timedelta(minutes=10)).timestamp()), "networkpulse_role": "analyst"}
    good = jwt.encode(claims, private, algorithm="RS256")
    assert verifier.verify(good) == Principal("researcher-123", "analyst")
    bad_role = jwt.encode({**claims, "networkpulse_role": "unknown"}, private, algorithm="RS256")
    with pytest.raises(HTTPException) as exc:
        verifier.verify(bad_role)
    assert exc.value.status_code == 403
    expired = jwt.encode({**claims, "exp": int((now-timedelta(minutes=10)).timestamp())}, private, algorithm="RS256")
    with pytest.raises(HTTPException) as exc:
        verifier.verify(expired)
    assert exc.value.status_code == 401
    wrong_audience = jwt.encode({**claims, "aud": "another-app"}, private, algorithm="RS256")
    with pytest.raises(HTTPException):
        verifier.verify(wrong_audience)
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = jwt.encode(claims, attacker_key, algorithm="RS256")
    with pytest.raises(HTTPException):
        verifier.verify(forged)


def test_https_required():
    with pytest.raises(ValueError, match="HTTPS"):
        TokenVerifier("http://insecure.test", "app", "https://issuer.test/jwks")
