"""Operator-run signed V2 active host probe (requires real remote TLS and OIDC).

This tool cannot produce legitimate deployment evidence from a laboratory CI
fixture. Caller must supply the actual approved original model, signature,
trusted key store, valid OIDC analyst JWT, and remote HTTPS hostname.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

from networkpulse.feature_contract_v2 import FlowV2, V2_FEATURE_CONTRACT
from networkpulse.v2_signed_runtime import V2SignedRuntime


def probe(url: str, token: str, trusted: V2SignedRuntime,
          sample: list[FlowV2]) -> dict:
    address = urlparse(url)
    if (address.scheme != "https" or not address.hostname
            or address.username or address.password or address.query
            or address.fragment or address.path not in ("", "/")
            or not token.strip() or len(sample) < 1 or len(sample) > 100):
        raise ValueError("Real HTTPS origin, OIDC token and private V2 sample required")
    if any(flow.label is not None for flow in sample):
        raise ValueError("Raw ground truth labels must not enter live remote API")
    base = url.rstrip("/")
    # httpx default TLS verification checks the remote hostname and CA chain;
    # redirects are forbidden to avoid disclosing bearer tokens elsewhere.
    started = time.perf_counter()
    with httpx.Client(timeout=10, follow_redirects=False, verify=True,
                      trust_env=False) as client:
        r = client.get(base + "/health/ready")
        if r.status_code != 200:
            raise ValueError("Signed active readiness over trusted HTTPS failed")
        ready = r.json()
        if (ready.get("status") != "ready"
                or ready.get("signed_artifact_sha256") != trusted.artifact_sha256
                or ready.get("feature_contract") != V2_FEATURE_CONTRACT
                or ready.get("release_signature_verified") is not True):
            raise ValueError("Active host/model signing or V2 contract mismatch")
        rr = client.post(
            base + "/api/v2/score",
            headers={"Authorization": "Bearer " + token},
            json={"flows": [e.model_dump(mode="json") for e in sample]},
        )
        if rr.status_code != 200:
            raise ValueError("Active host failed actual authenticated V2 inference")
        remote = rr.json()
    elapsed_ms = (time.perf_counter() - started) * 1000
    local = trusted.score(sample)
    if (remote.get("artifact_sha256") != trusted.artifact_sha256
            or remote.get("feature_contract") != V2_FEATURE_CONTRACT
            or remote.get("scored") != len(sample)
            or remote.get("predictions") != local):
        raise ValueError("Signed deployed model produces different predictions")
    return {
        "status": "active_v2_signed_tls_oidc_inference_parity_observed",
        "schema_version": 1,
        "active_model_sha256": trusted.artifact_sha256,
        "remote_origin_host_sha256": hashlib.sha256(address.hostname.encode()).hexdigest(),
        "tls_system_ca_hostname_check": True,
        "external_oidc_bearer_used": True,
        "sample_prediction_parity": True,
        "sample_size": len(sample),
        "client_measured_roundtrip_ms": round(elapsed_ms, 3),
        "signed_release_operator_evidence_is_externally_audited": False,
        "independent_site_ground_truth_verified_by_this_probe": False,
        "p0_operational_ml_acceptance": "NO_GO",
        "limitations": [
            "Single client probe does not prove uptime, signed deployment durability, or workload SLO.",
            "Local signed receipt provenance, independent labels, and field site need separate human audit.",
            "Physical Zeek/Suricata live sensor parity requires separate deployment evidence.",
        ],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--remote-https-origin", required=True)
    p.add_argument("--approved-model", type=Path, required=True)
    p.add_argument("--frozen-manifest", type=Path, required=True)
    p.add_argument("--signed-approval", type=Path, required=True)
    p.add_argument("--operator-trust-store", type=Path, required=True)
    p.add_argument("--expected-model-sha256", required=True)
    p.add_argument("--unlabeled-private-sample", type=Path, required=True)
    p.add_argument("--aggregate-output", type=Path, required=True)
    opts = p.parse_args()
    if opts.aggregate_output.exists():
        p.error("Will not overwrite externally observed live evidence")
    token = os.environ.get("NETWORKPULSE_V2_OPERATOR_OIDC_ACCESS_TOKEN")
    if not token:
        p.error("Requires real short-lived OIDC token in private process environment")
    trusted = V2SignedRuntime.open(
        opts.approved_model, opts.frozen_manifest,
        opts.signed_approval, opts.operator_trust_store,
        expected_sha256=opts.expected_model_sha256,
    )
    records = [
        FlowV2.model_validate_json(line)
        for line in opts.unlabeled_private_sample.read_text().splitlines()
        if line.strip()
    ]
    report = probe(opts.remote_https_origin, token, trusted, records)
    opts.aggregate_output.parent.mkdir(parents=True, exist_ok=True)
    with opts.aggregate_output.open("x", encoding="utf-8") as out:
        json.dump(report, out, sort_keys=True, indent=2)
        out.write("\n")
    print(json.dumps({
        "status": report["status"],
        "model": report["active_model_sha256"],
        "sample_size": report["sample_size"],
        "acceptance": "NO_GO",
    }))


if __name__ == "__main__":
    main()
