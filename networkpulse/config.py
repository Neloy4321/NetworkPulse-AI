"""Runtime settings. Read once per app instance; never log secrets."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database_url: str
    model_path: Path
    api_key: str
    model_sha256: str = ""
    max_batch: int = 250
    risk_threshold: float = 0.0
    max_body_bytes: int = 1_000_000
    mutation_rate_per_minute: int = 120
    auth_mode: str = "local"
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    oidc_role_claim: str = "networkpulse_role"
    redis_metrics_url: str = ""

    @classmethod
    def from_env(cls) -> Settings:
        key = os.getenv("NETWORKPULSE_API_KEY", "")
        mode = os.getenv("NETWORKPULSE_AUTH_MODE", "local").lower()
        if mode == "local" and len(key) < 16:
            raise ValueError("NETWORKPULSE_API_KEY must contain at least 16 characters")
        if mode not in {"local", "oidc"}:
            raise ValueError("NETWORKPULSE_AUTH_MODE must be local or oidc")
        if mode == "oidc" and not all(os.getenv(x) for x in (
            "NETWORKPULSE_OIDC_ISSUER", "NETWORKPULSE_OIDC_AUDIENCE", "NETWORKPULSE_OIDC_JWKS_URL"
        )):
            raise ValueError("OIDC requires issuer, audience, and JWKS URL")
        return cls(
            auth_mode=mode,
            oidc_issuer=os.getenv("NETWORKPULSE_OIDC_ISSUER", ""),
            oidc_audience=os.getenv("NETWORKPULSE_OIDC_AUDIENCE", ""),
            oidc_jwks_url=os.getenv("NETWORKPULSE_OIDC_JWKS_URL", ""),
            oidc_role_claim=os.getenv("NETWORKPULSE_OIDC_ROLE_CLAIM", "networkpulse_role"),
            database_url=os.getenv("DATABASE_URL", "sqlite:///./data/networkpulse.db"),
            model_path=Path(os.getenv("MODEL_PATH", "data/model.joblib")),
            model_sha256=os.getenv("MODEL_SHA256", ""),
            api_key=key,
            redis_metrics_url=os.getenv("REDIS_METRICS_URL", ""),
            max_batch=int(os.getenv("MAX_BATCH", "250")),
            max_body_bytes=int(os.getenv("MAX_BODY_BYTES", "1000000")),
            mutation_rate_per_minute=int(os.getenv("MUTATION_RATE_PER_MINUTE", "120")),
        )
