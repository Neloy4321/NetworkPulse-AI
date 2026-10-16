"""Fail-closed signed release admission and active inference for FlowV2.

A SHA pin protects bytes; an out-of-band Ed25519 trust store and a currently
valid operator-signed receipt protect authorization. Neither proves that
an operator's site/label claims are true: independent evidence is required.
No deployment or signing key is fabricated by this module.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
import sklearn

from networkpulse.feature_contract_v2 import FlowV2, V2_FEATURE_CONTRACT, features_v2
from networkpulse.release_approval import verify_signed_approval
from networkpulse.reliability import wilson_upper_bound

_ADMISSION_TOKEN = object()  # minted only after verified Ed25519 receipt

MIN_BENIGN = 200
MIN_ATTACK = 100
MAX_FPR_UPPER = 0.05
MIN_RECALL_LOWER = 0.80


def _count(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("Signed quality metric count must be nonnegative integer")
    return value


def wilson_lower_bound(successes: int, total: int) -> float:
    if total <= 0 or not 0 <= successes <= total:
        raise ValueError("Invalid attack support")
    # Dual of Wilson upper for failures; reuse exactly the production FPR method.
    return 1.0 - wilson_upper_bound(total - successes, total)


def assess_signed_release_quality(payload: dict, *, model_sha256: str) -> dict:
    """Enforce numerical AND release provenance gates from a verified receipt.

    IMPORTANT: Call only after Ed25519 verification against operator-owned
    public keys; a caller-built unsigned dictionary is not authorization.
    """
    if payload.get("candidate_sha256") != model_sha256:
        raise ValueError("Signed receipt is for a different artifact")
    for key in (
        "independent_site_verified", "live_sensor_contract_verified",
        "training_test_leakage_audited",
    ):
        if payload.get(key) is not True:
            raise ValueError("Independent site/sensor/leakage evidence absent")
    if payload.get("operation") != "promote":
        raise ValueError("Signed V2 runtime only accepts explicit promotion")
    if not isinstance(payload.get("approved_by"), str) or not payload["approved_by"].strip():
        raise ValueError("Missing independent human approver")
    evidence = payload.get("evaluation")
    if not isinstance(evidence, dict):
        raise ValueError("Missing signed independent-site quality evidence")
    benign = _count(evidence.get("benign_count"))
    attacks = _count(evidence.get("attack_count"))
    fp = _count(evidence.get("false_positives"))
    tp = _count(evidence.get("true_positives"))
    if benign < MIN_BENIGN or attacks < MIN_ATTACK or fp > benign or tp > attacks:
        raise ValueError("Insufficient or inconsistent real holdout support")
    if (evidence.get("feature_contract") != V2_FEATURE_CONTRACT
            or evidence.get("dataset_kind") != "independent_operator_site"
            or evidence.get("labels_independently_reviewed") is not True
            or evidence.get("deployed_sensor_parity_checked") is not True):
        raise ValueError("Missing site/ground-truth/V2 deployment contract verification")
    # Not just sample counts: require several independently collected days.
    site_days = _count(evidence.get("distinct_capture_days"))
    if site_days < 2:
        raise ValueError("Multiple independently collected days required")
    fpr_upper = wilson_upper_bound(fp, benign)
    recall_lower = wilson_lower_bound(tp, attacks)
    if fpr_upper > MAX_FPR_UPPER:
        raise ValueError("FPR Wilson upper exceeds signed production quality gate")
    if recall_lower < MIN_RECALL_LOWER:
        raise ValueError("Recall Wilson lower below signed production quality gate")
    return {
        "verified_numeric_gate": True,
        "benign_support": benign,
        "attack_support": attacks,
        "observed_false_positives": fp,
        "observed_true_positives": tp,
        "fpr_95_upper": fpr_upper,
        "attack_recall_95_lower": recall_lower,
        "capture_days": site_days,
        "human_claims_require_external_audit": True,
    }


@dataclass(frozen=True)
class V2SignedRuntime:
    """Trusted, signed release-only inference; no implicit fallback to v1."""

    artifact_sha256: str
    release_quality: dict
    vectorizer: object
    estimator: object
    threshold: float
    signer_key_id: str
    _admission_token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if self._admission_token is not _ADMISSION_TOKEN:
            raise ValueError("V2 runtime cannot be constructed without verified signed admission")

    @classmethod
    def open(
        cls, model_path: Path, manifest_path: Path,
        operator_receipt_path: Path, external_trust_store: Path, *,
        expected_sha256: str,
    ) -> V2SignedRuntime:
        if (not isinstance(expected_sha256, str) or len(expected_sha256) != 64
                or any(c not in "0123456789abcdef" for c in expected_sha256)):
            raise ValueError("Out-of-band reviewed SHA256 required")
        # First check expected checksum WITHOUT loading pickle.
        h = hashlib.sha256()
        with Path(model_path).open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(block)
        if h.hexdigest() != expected_sha256:
            raise ValueError("Active model bytes differ from approved SHA256")
        metadata = json.loads(Path(manifest_path).read_text("utf-8"))
        if (metadata.get("artifact_sha256") != expected_sha256
                or metadata.get("protocol", {}).get("feature_contract") != V2_FEATURE_CONTRACT
                or metadata.get("independent_test_performed") is not False
                or metadata.get("production_signed") is not False):
            raise ValueError("Source research lineage/immutability evidence unavailable")
        # A release receipt is separate from original unsigned research bundle;
        # the immutable model bytes are not modified to promote it.
        signed = verify_signed_approval(operator_receipt_path, external_trust_store)
        decision = assess_signed_release_quality(
            signed["payload"], model_sha256=expected_sha256
        )
        if metadata.get("protocol_sha256") is None:
            raise ValueError("Frozen training protocol fingerprint missing")
        threshold = metadata["protocol"].get("threshold")
        if (type(threshold) not in (int, float)
                or not 0.05 <= threshold <= 0.95):
            raise ValueError("Signed source-reviewed decision cutoff is invalid")
        # SHA-pinned and Ed25519-authorized model bytes may now be unpickled.
        blob = joblib.load(model_path)
        if (blob.get("schema_version") != 2
                or blob.get("research_only") is not True
                or blob.get("production_approved") is not False
                or blob.get("feature_contract") != V2_FEATURE_CONTRACT
                or blob.get("protocol_sha256") != metadata["protocol_sha256"]
                or blob.get("scikit_learn_version") != sklearn.__version__
                or blob.get("fixed_cutoff") != threshold):
            raise ValueError("Model runtime not equivalent to frozen V2 source contract")
        estimator = blob.get("estimator")
        if tuple(getattr(estimator, "classes_", ())) != (0, 1):
            raise ValueError("Unexpected supervised classifier classes")
        return cls(
            artifact_sha256=expected_sha256,
            release_quality=decision,
            vectorizer=blob["vectorizer"],
            estimator=estimator,
            threshold=float(threshold),
            signer_key_id=signed["signer_key_id"],
            _admission_token=_ADMISSION_TOKEN,
        )

    def score(self, flows: list[FlowV2]) -> list[dict]:
        if len(flows) > 512:
            raise ValueError("Bounded signed model inference batch exceeded")
        if not all(isinstance(e, FlowV2) for e in flows):
            raise TypeError("Signed V2 runtime accepts only lossless FlowV2")
        if not flows:
            return []
        # No ground truth labels admitted into live model calls.
        if any(flow.label is not None for flow in flows):
            raise ValueError("Production inference cannot be given training labels")
        encoded = self.vectorizer.transform([features_v2(e) for e in flows])
        probabilities = self.estimator.predict_proba(encoded)
        if probabilities.shape != (len(flows), 2):
            raise ValueError("Frozen model output shape mismatch")
        scores = probabilities[:, 1]
        if not np.isfinite(scores).all() or (scores < 0).any() or (scores > 1).any():
            raise ValueError("Invalid probabilistic output")
        return [
            {
                "anomalous": bool(value >= self.threshold),
                "probability": round(float(value), 6),
                "threshold": self.threshold,
                "feature_contract": V2_FEATURE_CONTRACT,
            }
            for value in scores
        ]
