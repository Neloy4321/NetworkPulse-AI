"""Signed site-evidence linkage tests; synthetic samples are not field proof."""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from networkpulse.deployment_evidence import (
    canonical_json, verify_deployment_evidence, read_evidence,
)


def fixture(tmp_path):
    model_sha = "3" * 64
    corpus_sha = "4" * 64
    external = {
        "status": "passed", "schema_version": 1,
        "scope": "frozen_cross_domain_labeled_holdout_not_field_certification",
        "model_sha256": model_sha, "holdout_sha256": corpus_sha,
        "training_ids_overlap": 0, "unique_holdout_events": 250,
        "class_counts": {"benign": 150, "anomaly": 100},
    }
    staging = {
        "status": "passed", "schema_version": 1,
        "scope": "isolated_staging_real_redis_postgresql",
        "model_sha256": model_sha, "source_sha256": corpus_sha,
        "published": 250, "acknowledged_after_commit": 250,
        "persisted_unique_event_ids": 250, "new_sql_rows_inserted": 250,
        "pending": 0, "dead_letters": 0,
        "queue_to_ack_seconds": {"p99": .5},
        "acceptance": {"max_p99_queue_seconds": 1,
                       "min_verified_throughput": 2},
        "verified_flows_per_second": 5,
    }
    efile, sfile = tmp_path / "external.json", tmp_path / "staging.json"
    efile.write_text(json.dumps(external))
    sfile.write_text(json.dumps(staging))
    att = {
        "schema_version": 1,
        "environment": "isolated_staging",
        "sensor_capture_operator_attested": True,
        "approved_staging_execution_attested": True,
        "model_sha256": model_sha,
        "external_report_sha256": hashlib.sha256(efile.read_bytes()).hexdigest(),
        "staging_report_sha256": hashlib.sha256(sfile.read_bytes()).hexdigest(),
        "operator_identity": "staging-owner",
        "staging_capture_reference": "ticket-staging-1093",
        "review_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "topology": "single_node",
    }
    key = Ed25519PrivateKey.generate()
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    afile, sigfile, pubfile = (
        tmp_path / "attestation.json", tmp_path / "attestation.sig",
        tmp_path / "trusted.pub.pem",
    )
    afile.write_text(json.dumps(att))
    sigfile.write_text(base64.b64encode(key.sign(canonical_json(att))).decode())
    pubfile.write_bytes(public_key)
    paths = dict(external_report=efile, staging_report=sfile,
                 attestation_file=afile, signature_file=sigfile,
                 public_key_file=pubfile)
    return paths


def test_matching_signed_evidence_is_review_ready_but_never_certified(tmp_path):
    report = verify_deployment_evidence(**fixture(tmp_path))
    assert report["status"] == "integrity_passed_independent_site_review_required"
    assert report["operator_signature_valid"] is True
    assert report["production_certified"] is False
    assert report["holdout_rows"] == 250


def test_signed_operator_attestation_tampering_is_rejected(tmp_path):
    paths = fixture(tmp_path)
    att = json.loads(paths["attestation_file"].read_text())
    att["topology"] = "multi_node"
    paths["attestation_file"].write_text(json.dumps(att))
    with pytest.raises(ValueError, match="signature invalid"):
        verify_deployment_evidence(**paths)


def test_mutated_metrics_report_with_original_signature_is_rejected(tmp_path):
    paths = fixture(tmp_path)
    report = json.loads(paths["staging_report"].read_text())
    report["acknowledged_after_commit"] -= 1
    paths["staging_report"].write_text(json.dumps(report))
    with pytest.raises(ValueError, match="fingerprints"):
        verify_deployment_evidence(**paths)


def test_json_duplicate_property_rejected(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"status":"passed","status":"failed"}')
    with pytest.raises(ValueError, match="Duplicate"):
        read_evidence(path)
