"""Isolated signed V2 inference service, fail-closed authentication by default.

This module is an opt-in service interface, NOT a deployed endpoint.
It never accepts unsigned RF models and never replaces the live legacy API.
The calling deployment must provide real OIDC verifier + trusted signer keys.
"""
from __future__ import annotations

from typing import Protocol

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from networkpulse.feature_contract_v2 import FlowV2, V2_FEATURE_CONTRACT
from networkpulse.v2_signed_runtime import V2SignedRuntime


class _Principal(Protocol):
    def require(self, role: str) -> None: ...


class _Verifier(Protocol):
    def verify(self, token: str) -> _Principal: ...


class ScoreBatchV2(BaseModel):
    model_config = ConfigDict(extra="forbid")
    flows: list[FlowV2] = Field(min_length=1, max_length=512)


def create_signed_v2_app(*, runtime: V2SignedRuntime,
                         verifier: _Verifier) -> FastAPI:
    """The caller must FIRST open exact-SHA, Ed25519-approved V2 runtime."""
    if not isinstance(runtime, V2SignedRuntime) or verifier is None:
        raise ValueError("Signed V2 runtime and OIDC verifier are required")
    app = FastAPI(
        title="NetworkPulse Signed V2 Inference",
        version="0.1.0",
        openapi_url=None, docs_url=None, redoc_url=None,
    )

    def authorized(authorization: str | None = Header(default=None)):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="OIDC Bearer access required")
        try:
            principal = verifier.verify(authorization[len("Bearer "):])
            principal.require("analyst")
            return principal
        except Exception as exc:
            raise HTTPException(
                status_code=403, detail="Invalid or unauthorized OIDC principal"
            ) from exc

    @app.get("/health/live")
    def live():
        return {"status": "live"}

    @app.get("/health/ready")
    def ready():
        return {
            "status": "ready",
            "feature_contract": V2_FEATURE_CONTRACT,
            "signed_artifact_sha256": runtime.artifact_sha256,
            # No field-groundtruth or independent-site claims in readiness.
            "release_signature_verified": True,
            "warning": "Signed artifact/receipt is not external site truth verification",
        }

    @app.post("/api/v2/score")
    def predict(payload: ScoreBatchV2, _=Depends(authorized)):
        predictions = runtime.score(payload.flows)
        # Do not echo UID, IP addresses or raw inputs to the caller.
        return {
            "feature_contract": V2_FEATURE_CONTRACT,
            "artifact_sha256": runtime.artifact_sha256,
            "scored": len(predictions),
            "predictions": predictions,
        }

    return app
