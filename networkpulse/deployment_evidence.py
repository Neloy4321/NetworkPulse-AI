"""Signed evidence linkage for approved real-domain and staging acceptance.

Verifies operator signature and mutually consistent immutable artifact digests.
This does NOT verify a site was actually operated or certify production/HA.
"""
from __future__ import annotations

import base64
import json
import math
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from networkpulse.generalization_evidence import valid_sha


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object property in evidence")
        result[key] = value
    return result


def read_evidence(path: Path, *, max_size=1_000_000) -> dict:
    if path.stat().st_size > max_size:
        raise ValueError("Evidence file exceeds bounded size")
    with path.open("rt", encoding="utf-8") as f:
        obj = json.load(f, object_pairs_hook=_unique_pairs,
                        parse_constant=lambda value: (_ for _ in ()).throw(
                            ValueError("Non-finite JSON constant")))
    if not isinstance(obj, dict):
        raise ValueError("Evidence JSON must be an object")
    return obj


def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      allow_nan=False, ensure_ascii=False).encode("utf-8")


def signed_staging_attestation(attestation: dict, signature_base64: str,
                               public_key_pem: bytes) -> None:
    """Only key already approved out of band is trusted, never embedded key."""
    key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Independent staging attestation requires Ed25519 public key")
    try:
        signature = base64.b64decode(signature_base64, validate=True)
        if len(signature) != 64:
            raise ValueError("Ed25519 detached signature must be 64 bytes")
        key.verify(signature, canonical_json(attestation))
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("Staging attestation signature invalid") from exc


def verify_deployment_evidence(*, external_report: Path, staging_report: Path,
                               attestation_file: Path, signature_file: Path,
                               public_key_file: Path) -> dict:
    """Require signed operator assertion and actual outcome consistency."""
    from networkpulse.generalization_evidence import digest_file
    external = read_evidence(external_report)
    staging = read_evidence(staging_report)
    att = read_evidence(attestation_file)
    signed_staging_attestation(
        att, signature_file.read_text(encoding="ascii").strip(),
        public_key_file.read_bytes(),
    )
    expected = {
        "schema_version", "environment", "sensor_capture_operator_attested",
        "approved_staging_execution_attested", "model_sha256",
        "external_report_sha256", "staging_report_sha256",
        "operator_identity", "staging_capture_reference",
        "review_timestamp_utc", "topology",
    }
    if set(att) != expected or att["schema_version"] != 1:
        raise ValueError("Staging operator attestation schema mismatch")
    if (att["environment"] != "isolated_staging" or
            att["sensor_capture_operator_attested"] is not True or
            att["approved_staging_execution_attested"] is not True or
            att["topology"] not in ("single_node", "multi_node")):
        raise ValueError("No signed authorization for independent staging capture")
    if (not isinstance(att["operator_identity"], str)
            or len(att["operator_identity"].strip()) < 3
            or not isinstance(att["staging_capture_reference"], str)
            or len(att["staging_capture_reference"].strip()) < 8):
        raise ValueError("Missing independent staging operator identity/reference")
    for attr in ("model_sha256", "external_report_sha256", "staging_report_sha256"):
        if not valid_sha(att[attr]):
            raise ValueError("Attestation contains malformed pinned SHA256")
    if (digest_file(external_report) != att["external_report_sha256"] or
            digest_file(staging_report) != att["staging_report_sha256"]):
        raise ValueError("Evidence bytes do not match operator-signed fingerprints")
    if (external.get("status") != "passed" or
            external.get("scope") != "frozen_cross_domain_labeled_holdout_not_field_certification"):
        raise ValueError("Frozen independent holdout acceptance did not pass")
    if (staging.get("status") != "passed" or
            staging.get("scope") != "isolated_staging_real_redis_postgresql"):
        raise ValueError("Actual operator staging-load report did not pass")
    pin = att["model_sha256"]
    if not (pin == external.get("model_sha256") == staging.get("model_sha256")):
        raise ValueError("Model identity differs between external holdout and deployment")
    if external.get("holdout_sha256") != staging.get("source_sha256"):
        raise ValueError("Staging evidence used another dataset than evaluated holdout")
    if (external.get("training_ids_overlap") != 0 or
            external.get("class_counts", {}).get("benign", 0) <= 0 or
            external.get("class_counts", {}).get("anomaly", 0) <= 0):
        raise ValueError("Holdout missing required labeled sample validation")
    published = staging.get("published")
    acknowledged = staging.get("acknowledged_after_commit")
    persisted = staging.get("persisted_unique_event_ids")
    inserted = staging.get("new_sql_rows_inserted")
    if not (type(published) is int and published > 0 and
            published == acknowledged == persisted == inserted):
        raise ValueError("Staging SQL/Redis exact-row reconciliation mismatch")
    if staging.get("pending") != 0 or staging.get("dead_letters") != 0:
        raise ValueError("Staging has unacknowledged or DLQ deliveries")
    latency = staging.get("queue_to_ack_seconds", {}).get("p99")
    ceiling = staging.get("acceptance", {}).get("max_p99_queue_seconds")
    throughput = staging.get("verified_flows_per_second")
    minimum = staging.get("acceptance", {}).get("min_verified_throughput")
    if not all(type(x) in (float, int) and math.isfinite(x) and x >= 0
               for x in (latency, ceiling, throughput, minimum)):
        raise ValueError("Invalid staging latency and throughput measurements")
    if latency > ceiling or throughput < minimum:
        raise ValueError("Staging metric gate not met")
    return {
        "schema_version": 1,
        "status": "integrity_passed_independent_site_review_required",
        "production_certified": False,
        "operator_signature_valid": True,
        "model_sha256": pin,
        "external_report_sha256": att["external_report_sha256"],
        "staging_report_sha256": att["staging_report_sha256"],
        "holdout_rows": external["unique_holdout_events"],
        "staging_unique_rows": persisted,
        "topology_operator_attested": att["topology"],
        "outstanding_requirements": [
            "Independent review of operator identity and capture provenance",
            "Real topology-specific node failover and site RPO/RTO evidence",
            "Traffic-representative alert latency and capacity soak verification",
            "Independent security and ML safety sign-off before production rollout",
        ],
    }
