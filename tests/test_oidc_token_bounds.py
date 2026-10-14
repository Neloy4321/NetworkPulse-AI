"""Reject malformed and oversized JWTs before JWKS resolution."""
import pytest
from fastapi import HTTPException

from networkpulse.security.oidc import TokenVerifier


def test_bad_token_size_rejected_without_network_or_key_lookup():
    verifier = TokenVerifier("https://issuer.test", "audience", "https://issuer.test/jwks")

    def lookup(token):
        raise AssertionError("Untrusted oversized token must not reach JWKS lookup")

    verifier.jwks.get_signing_key_from_jwt = lookup
    for token in ("", "abc", "x" * 8193):
        with pytest.raises(HTTPException) as error:
            verifier.verify(token)
        assert error.value.status_code == 401
