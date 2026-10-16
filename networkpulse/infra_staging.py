"""Stage A: isolated infrastructure-only staging, never an IDS or model server.

This deliberately does not import Detector, scoring, training, model-registry
or legacy application factories. No model can be implicitly approved or served.
Actual production-like staging requires a real HTTPS OIDC issuer and separate
PostgreSQL and Redis identities; mocked CI can verify security *code* only.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from urllib.parse import urlsplit

import psycopg
import redis
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from prometheus_client import CollectorRegistry, Gauge, generate_latest

from networkpulse.security.oidc import Principal, TokenVerifier

STAGING_MODE = "non_ml_infrastructure_only"
DATABASE_NAME = "networkpulse_staging_infra"


def _secret(name: str) -> str:
    value = os.environ.get(name, "")
    if (len(value) < 20 or value != value.strip()
            or value.lower().startswith(("changeme", "password", "replace-me", "example"))):
        raise ValueError(f"{name} must be a non-placeholder secret of at least 20 characters")
    return value


def _https_url(name: str) -> str:
    value = os.environ.get(name, "")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname
            or parsed.username or parsed.password or parsed.fragment or parsed.query):
        raise ValueError(f"{name} requires a trusted HTTPS origin/URL")
    return value


@dataclass(frozen=True)
class InfraStagingSettings:
    db_host: str
    db_password: str
    redis_host: str
    redis_password: str
    oidc_issuer: str
    oidc_jwks_url: str
    oidc_audience: str
    oidc_role_claim: str

    @classmethod
    def from_env(cls) -> InfraStagingSettings:
        if os.getenv("NETWORKPULSE_STAGING_MODE") != STAGING_MODE:
            raise ValueError("Only explicitly isolated non-ML infrastructure staging is supported")
        # Fixed application DB identity keeps the synthetic test harness
        # separate from the main product's operational database.
        if os.getenv("NETWORKPULSE_STAGING_DB_NAME", DATABASE_NAME) != DATABASE_NAME:
            raise ValueError("Infrastructure staging refuses non-staging PostgreSQL database")
        db_host = os.getenv("NETWORKPULSE_STAGING_DB_HOST", "db")
        redis_host = os.getenv("NETWORKPULSE_STAGING_REDIS_HOST", "redis")
        if not db_host or not redis_host or any(
            p in str(x) for x in (db_host, redis_host) for p in ("/", "@", " ")
        ):
            raise ValueError("Invalid infrastructure dependency hostname")
        audience = os.getenv("NETWORKPULSE_STAGING_OIDC_AUDIENCE", "")
        role_claim = os.getenv("NETWORKPULSE_STAGING_OIDC_ROLE_CLAIM", "networkpulse_role")
        if not audience or not role_claim or len(audience) > 256 or len(role_claim) > 128:
            raise ValueError("Stage A OIDC audience and role claim are required")
        return cls(
            db_host=db_host,
            db_password=_secret("NETWORKPULSE_STAGING_DB_PASSWORD"),
            redis_host=redis_host,
            redis_password=_secret("NETWORKPULSE_STAGING_REDIS_PASSWORD"),
            oidc_issuer=_https_url("NETWORKPULSE_STAGING_OIDC_ISSUER"),
            oidc_jwks_url=_https_url("NETWORKPULSE_STAGING_OIDC_JWKS_URL"),
            oidc_audience=audience,
            oidc_role_claim=role_claim,
        )


class DependencyChecks:
    """Real private-network probes; no schema mutation, ML, or test event ingestion."""

    def __init__(self, settings: InfraStagingSettings):
        self.settings = settings
        self.redis = redis.Redis(
            host=settings.redis_host, port=6379, password=settings.redis_password,
            socket_connect_timeout=2, socket_timeout=2, retry_on_timeout=False,
        )

    def postgres_ready(self) -> bool:
        with psycopg.connect(
            host=self.settings.db_host, port=5432, dbname=DATABASE_NAME,
            user="networkpulse_staging", password=self.settings.db_password,
            connect_timeout=2, options="-c default_transaction_read_only=on",
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                return cursor.fetchone() == (1,)

    def redis_ready(self) -> bool:
        return self.redis.ping() is True

    def close(self) -> None:
        self.redis.close()


def create_app(
    settings: InfraStagingSettings | None = None,
    *,
    verifier: TokenVerifier | None = None,
    checks: DependencyChecks | None = None,
) -> FastAPI:
    settings = settings or InfraStagingSettings.from_env()
    verifier = verifier or TokenVerifier(
        settings.oidc_issuer, settings.oidc_audience, settings.oidc_jwks_url,
        settings.oidc_role_claim,
    )
    checks = checks or DependencyChecks(settings)
    registry = CollectorRegistry()
    up = Gauge(
        "networkpulse_infra_staging_dependency_up",
        "Verified independent infrastructure staging dependency readiness",
        ["dependency"], registry=registry,
    )
    up.labels(dependency="postgres").set(0)
    up.labels(dependency="redis").set(0)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        try:
            yield
        finally:
            checks.close()

    app = FastAPI(
        title="NetworkPulse NON-ML staging infrastructure",
        docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan,
    )

    @app.middleware("http")
    async def no_cache_and_security_headers(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    def identity(authorization: str | None = Header(default=None)) -> Principal:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, detail="Real OIDC Bearer access token required")
        # Do not catch HTTPException and turn a failed 401 into 500/403.
        return verifier.verify(authorization[7:])

    def minimum(role: str):
        def guarded(principal: Principal = Depends(identity)) -> Principal:
            principal.require(role)
            return principal
        return guarded

    @app.get("/health/live")
    def live():
        return {"status": "live", "mode": STAGING_MODE}

    @app.get("/health/ready")
    def ready():
        state = {}
        for name, operation in (
            ("postgres", checks.postgres_ready),
            ("redis", checks.redis_ready),
        ):
            try:
                state[name] = operation() is True
            except Exception:
                state[name] = False
            up.labels(dependency=name).set(1 if state[name] else 0)
        if not all(state.values()):
            # Do not reveal private hostnames, DB user/password or stack traces.
            raise HTTPException(503, detail="Staging infrastructure dependency unavailable")
        return {
            "status": "ready",
            "mode": STAGING_MODE,
            "model_loaded": False,
            "ml_acceptance_claimed": False,
            "dependencies": {"postgres": "ready", "redis": "ready"},
        }

    @app.get("/internal/metrics", response_class=PlainTextResponse)
    def internal_metrics():
        return PlainTextResponse(
            generate_latest(registry).decode("utf-8"),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get("/api/staging/viewer")
    def viewer(principal: Principal = Depends(minimum("viewer"))):
        return {"role": principal.role, "mode": STAGING_MODE, "model_loaded": False}

    @app.get("/api/staging/analyst")
    def analyst(principal: Principal = Depends(minimum("analyst"))):
        return {"role": principal.role, "mode": STAGING_MODE, "model_loaded": False}

    @app.get("/api/staging/admin")
    def admin(principal: Principal = Depends(minimum("admin"))):
        return {"role": principal.role, "mode": STAGING_MODE, "model_loaded": False}

    return app


def create_production_like_staging_app() -> FastAPI:
    """Uvicorn factory requires actual separately provisioned staging credentials."""
    return create_app()
