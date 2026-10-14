"""Read-only deployment-to-runtime model release contract.

Ensures the exact model deployed to an API/worker is the registry's active
candidate and matches the operator-configured MODEL_SHA256 pin. This does not
prove independent site evaluation, host integrity or distributed rollout safety.
"""
from __future__ import annotations

import hmac
import os
import re
from pathlib import Path

from networkpulse.features import FEATURE_VERSION
from networkpulse.model_registry import ModelRegistry


def verify_deployment_model(*, model_path: Path, expected_sha256: str,
                            registry_root: Path) -> dict:
    """Fail closed before unpickling or processing flows; no state is mutated."""
    if not isinstance(expected_sha256, str) or not re.fullmatch(
        r"[0-9a-fA-F]{64}", expected_sha256
    ):
        raise ValueError("NP-REL-001: MODEL_SHA256 must be a complete 64-hex pin")
    if not registry_root or not str(registry_root).strip():
        raise ValueError("NP-REL-002: model registry root is required")
    checked = ModelRegistry(Path(registry_root)).verify_active(Path(model_path))
    if not hmac.compare_digest(checked["sha256"], expected_sha256.lower()):
        raise ValueError("NP-REL-003: configured model pin differs from approved active release")
    if checked.get("feature_version") != FEATURE_VERSION:
        raise ValueError("NP-REL-004: active model feature contract is incompatible")
    if checked.get("synthetic_only"):
        raise ValueError("NP-REL-005: synthetic/demo registry release refused")
    if checked.get("production_approved") is not True:
        raise ValueError("NP-REL-006: active release lacks recorded signed production approval")
    return {
        "verified": True, "active": checked["active"],
        "sha256": checked["sha256"], "feature_version": FEATURE_VERSION,
        "scope": "single-node filesystem / registry / configured pin consistency",
        "warning": "Not proof of independent model validation or multi-replica agreement",
    }


def require_runtime_release(settings) -> dict | None:
    """Production requires registry verification; development stays opt-in.

    Workers in the production Compose overlay opt in using the same registry
    root even though worker processes do not configure interactive OIDC login.
    """
    root = os.getenv("NETWORKPULSE_MODEL_REGISTRY_ROOT", "").strip()
    if settings.deployment_mode == "production" and not root:
        raise ValueError("NP-REL-002: production requires NETWORKPULSE_MODEL_REGISTRY_ROOT")
    if not root:
        return None
    return verify_deployment_model(
        model_path=settings.model_path, expected_sha256=settings.model_sha256,
        registry_root=Path(root),
    )
