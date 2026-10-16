"""Prospective SHA-locked research-only external scoring, NOT operational approval.

Evaluation accepts trusted, independently prepared and genuinely labeled
canonical JSONL. It never fabricates counters, host IDs, connection states,
site independence, operator sign-off or deployed artifact parity. DO NOT load
unknown model pickle files: pin the expected model SHA out of band first.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import joblib

from networkpulse.evaluation.frozen_rf_research import (
    FIXED_CUTOFF, score_verified_bundle, verify_bundle_checksum,
)
from networkpulse.evaluation.unsw_to_toniot import digest, metrics, unique
from networkpulse.schemas import FlowEvent

MAX_ROWS = 300000
_MAX_TARGET_INVALID = 0
_EXPOSED_SOURCE_FAMILIES = frozenset({
    "unsw-nb15", "ton-iot", "cic-ids2017",
})


def validate_target_attestation(payload: dict, *, target_sha256: str) -> dict:
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("missing prospective source attestation schema")
    required = (
        "dataset_family", "source_operator", "authorization_reference",
        "label_review_method", "native_sensor_contract",
        "site_provenance_kind", "capture_period_utc", "pre_registration_reference",
    )
    for field in required:
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip() or len(value) > 400:
            raise ValueError("missing or invalid source provenance field: " + field)
    if payload.get("canonical_jsonl_sha256") != target_sha256:
        raise ValueError("target SHA256 does not match out-of-band provenance")
    if payload["dataset_family"].strip().lower() in _EXPOSED_SOURCE_FAMILIES:
        raise ValueError("known previously exposed family cannot be new target")
    if payload["site_provenance_kind"] not in (
        "separate_laboratory", "independent_operator_attested"
    ):
        raise ValueError("unsupported claimed source category")
    if payload.get("labels_are_independently_adjudicated") is not True:
        raise ValueError("genuine labels must have a documented independent review")
    if payload.get("reviewer_confirmed_frozen_model_before_target") is not True:
        raise ValueError("model must be frozen before any target label review")
    # Source statements cannot be automatically audited for truth by code.
    return {
        "source_family_digest": hashlib.sha256(
            payload["dataset_family"].encode()
        ).hexdigest(),
        "operator_reference_digest": hashlib.sha256(
            payload["authorization_reference"].encode()
        ).hexdigest(),
        "site_claim": payload["site_provenance_kind"],
        "source_attestation_submitted_not_independently_verified": True,
        "site_independence_verified": False,
        "label_taxonomy_verified_by_independent_reviewer": False,
    }


def read_verified_canonical(path: Path, expected_sha256: str):
    if digest(path) != expected_sha256:
        raise ValueError("new labeled canonical data SHA256 changed")
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for raw in handle:
            if not raw.strip():
                raise ValueError("unlabeled empty source line not accepted")
            if len(rows) >= MAX_ROWS:
                raise ValueError("prospective evaluator input row ceiling exceeded")
            try:
                event = FlowEvent.model_validate_json(raw)
            except Exception as exc:
                raise ValueError("invalid native canonical labeled source row") from exc
            if (event.label not in ("benign", "anomaly") or
                    event.source in ("simulator",)):
                raise ValueError("unlabeled or simulated source not acceptable")
            rows.append(event)
    if digest(path) != expected_sha256:
        raise ValueError("prospective raw canonical source mutated during scoring")
    if not rows:
        raise ValueError("independent labeled source is empty")
    unique_rows, duplicates = unique(rows)
    return unique_rows, duplicates


def evaluate(
    *,
    trusted_bundle_path: Path,
    manifest_path: Path,
    expected_bundle_sha256: str,
    canonical_labeled_path: Path,
    expected_target_sha256: str,
    source_attestation_path: Path,
) -> dict:
    verify_bundle_checksum(trusted_bundle_path, expected_bundle_sha256)
    frozen = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (frozen.get("bundle_sha256") != expected_bundle_sha256 or
            frozen.get("status") != "source_only_supervised_research_bundle_frozen" or
            frozen.get("production_approved") is not False or
            frozen.get("operator_signed") is not False):
        raise ValueError("source-only frozen bundle manifest mismatch")
    # ONLY SHA-PINNED AND TRUSTED LOCAL ARTIFACTS MAY BE UNPICKLED.
    bundle = joblib.load(trusted_bundle_path)
    if (bundle.get("source_sha256") != frozen.get("source_zip_sha256") or
            bundle.get("protocol_sha256") != frozen.get("protocol_sha256")):
        raise ValueError("frozen source training protocol mismatch")
    attestation = json.loads(
        source_attestation_path.read_text(encoding="utf-8")
    )
    provenance = validate_target_attestation(
        attestation, target_sha256=expected_target_sha256
    )
    # Verify before scoring: labels never affect features, model, threshold.
    events, duplicates = read_verified_canonical(
        canonical_labeled_path, expected_target_sha256
    )
    counts = Counter(e.label for e in events)
    if counts["benign"] < 200 or counts["anomaly"] < 100:
        raise ValueError("independent target needs >=200 benign and >=100 attack rows")
    scores = score_verified_bundle(bundle, events)
    results = metrics(events, [
        SimpleNamespace(
            anomalous=bool(s >= FIXED_CUTOFF), anomaly_score=float(s)
        ) for s in scores
    ])
    results.pop("operational_gate", None)
    from networkpulse.evaluation.source_only_readiness import (
        MAX_FPR_UPPER, MIN_RECALL_LOWER,
    )
    numeric = (
        results["fpr_wilson95"][1] <= MAX_FPR_UPPER and
        results["recall_wilson95"][0] >= MIN_RECALL_LOWER
    )
    return {
        "schema_version": 1,
        "status": "prospective_external_research_numeric_measurement_only",
        "research_only": True,
        "operational_ml_acceptance_demonstrated": False,
        "production_deployment_verified": False,
        "active_signed_artifact_equivalence_verified": False,
        "training_test_cross_dataset_overlap_audited": False,
        "target_dataset_sha256": expected_target_sha256,
        "frozen_research_bundle_sha256": expected_bundle_sha256,
        "source_provenance": provenance,
        "target_unique_rows": len(events),
        "duplicates_within_target_removed": duplicates,
        "source_numeric_gate_research_only_met": numeric,
        "evaluation": results,
        "limitations": [
            "No independent trust anchor verifies provenance or label adjudication.",
            "No private source-train flow ledger to test cross-dataset duplicate overlap.",
            "Independently operated site cannot be verified from an input JSON file.",
            "Result is research numeric quality only, never production acceptance.",
            "Research RF does not replace deployed native IsolationForest Detector.",
            "Artifact SHA pins integrity, not signed operator authenticity.",
            "Flow-level Wilson intervals ignore correlated site sessions.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-bundle-sha256", required=True)
    parser.add_argument("--labeled-canonical-jsonl", type=Path, required=True)
    parser.add_argument("--expected-target-sha256", required=True)
    parser.add_argument("--source-attestation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("cannot rewrite an existing prospective research result")
    report = evaluate(
        trusted_bundle_path=args.bundle,
        manifest_path=args.manifest,
        expected_bundle_sha256=args.expected_bundle_sha256,
        canonical_labeled_path=args.labeled_canonical_jsonl,
        expected_target_sha256=args.expected_target_sha256,
        source_attestation_path=args.source_attestation,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")
    print(json.dumps({
        "status": report["status"],
        "numeric_research_gate_met": report["source_numeric_gate_research_only_met"],
        "source_family_digest": report["source_provenance"]["source_family_digest"],
        "operational_ml_acceptance_demonstrated": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
