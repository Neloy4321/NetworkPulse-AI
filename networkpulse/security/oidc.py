"""OIDC access token verification for real external identity providers.

The deployment operator configures trusted issuer, JWKS endpoint, audience and
claim mapping. Only RS256 is accepted. No JWT is minted by the application.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from fastapi import HTTPException

ROLES = {"viewer": 0, "analyst": 1, "admin": 2}


@dataclass(frozen=True)
class Principal:
    subject: str
    role: str

    def require(self, minimum: str) -> None:
        if ROLES.get(self.role, -1) < ROLES[minimum]:
            raise HTTPException(403, detail="Insufficient role")


class TokenVerifier:
    def __init__(self, issuer: str, audience: str, jwks_url: str, role_claim: str = "networkpulse_role"):
        if not issuer.startswith("https://") or not jwks_url.startswith("https://"):
            raise ValueError("OIDC issuer and JWKS endpoint must use HTTPS")
        if not audience or not role_claim:
            raise ValueError("OIDC audience and role claim must be configured")
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.role_claim = role_claim
        import jwt
        self.jwt = jwt
        self.jwks = jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=600, timeout=4)

    def verify(self, token: str) -> Principal:
        try:
            signing_key = self.jwks.get_signing_key_from_jwt(token)
            claims = self.jwt.decode(token, signing_key.key, algorithms=["RS256"],
                                     issuer=self.issuer, audience=self.audience,
                                     options={"require": ["exp", "iat", "iss", "sub", "aud"]},
                                     leeway=30)
        except self.jwt.PyJWTError as exc:
            raise HTTPException(401, detail="Invalid or expired access token") from exc
        role = claims.get(self.role_claim)
        if isinstance(role, list):
            role = next((x for x in ("admin", "analyst", "viewer") if x in role), None)
        if role not in ROLES:
            raise HTTPException(403, detail="Token missing NetworkPulse role")
        return Principal(subject=str(claims["sub"]), role=role)


def verify_api_key(provided: str | None, configured: str) -> bool:
    return bool(provided) and secrets.compare_digest(provided, configured)
