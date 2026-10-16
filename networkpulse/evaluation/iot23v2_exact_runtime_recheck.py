"""Previously exposed IoT-23v2 research corroboration; NEVER production acceptance.

Pinned SOURCE bytes and the exact previously frozen RF are evaluated in the
original CI runtime. Model or threshold must NOT be altered after the source
label inspection performed on 2026-10-16. Dataset uses rule-assisted labels,
not independent SOC-adjudicated ground truth. Complete-case selection is large
and label-dependent; results cannot stand for the complete capture.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

import joblib

from networkpulse.evaluation.frozen_rf_research import (
    FIXED_CUTOFF, score_verified_bundle, verify_bundle_checksum,
)
from networkpulse.evaluation.iot23v2_source_adapter import inspect_and_convert
from networkpulse.evaluation.prospective_external_rf import read_verified_canonical
from networkpulse.evaluation.source_only_readiness import (
    MAX_FPR_UPPER, MIN_RECALL_LOWER,
)
from networkpulse.evaluation.unsw_to_toniot import digest, metrics
from networkpulse.generalization_evidence import (
    load_training_keys, normalized_flow_fingerprint,
)

# This hash was recorded from the user's uploaded 2026-10-16 file BEFORE
# any exact-runtime inference. All source-side RF training predated this.
SOURCE_SHA256 = "7d1d052835439d77dae246b588d7628813bbdef21fdf3b323f4b3eb2c61ef146"
SOURCE_BYTES = 3019311
FROZEN_RF_SHA256 = "ba5fbc2cb171b0f79a31d99e71fbe438135325babc9d939d26c8589f66ff954b"


def run(original: Path, bundle_path: Path, manifest_path: Path,
        ledger_path: Path) -> dict:
    if original.stat().st_size != SOURCE_BYTES or digest(original) != SOURCE_SHA256:
        raise ValueError("IoT-23v2 approved capture size/SHA256 mismatch")
    if digest(bundle_path) != FROZEN_RF_SHA256:
        raise ValueError("previously frozen UNSW model SHA256 mismatch")
    frozen = json.loads(manifest_path.read_text("utf-8"))
    if (frozen.get("bundle_sha256") != FROZEN_RF_SHA256 or
            frozen.get("status") != "source_only_supervised_research_bundle_frozen" or
            frozen.get("research_only") is not True or
            frozen.get("production_approved") is not False or
            frozen.get("operator_signed") is not False):
        raise ValueError("trusted source-trained RF manifest invalid")
    # Sensitive training-derived hashes are never uploaded to an artifact.
    ledger = load_training_keys(ledger_path, frozen["training_ledger_sha256"])
    if len(ledger.canonical_ids) != frozen["training_unique"]:
        raise ValueError("incomplete source training ledger")
    verify_bundle_checksum(bundle_path, FROZEN_RF_SHA256)
    # Trusted CI-retrained source bundle, SHA verified before serialization load.
    model = joblib.load(bundle_path)
    if (model.get("sklearn_version") != __import__("sklearn").__version__ or
            model.get("protocol_sha256") != frozen["protocol_sha256"]):
        raise ValueError("runtime model version and frozen feature protocol mismatch")
    with tempfile.TemporaryDirectory(prefix="restricted-iot23-") as d:
        private = Path(d)
        canonical = private / "source-canonical.jsonl"
        schema_report = private / "aggregate-conversion.json"
        audit = inspect_and_convert(original, canonical, schema_report)
        events, duplicate_rows = read_verified_canonical(
            canonical, audit["canonical_sha256"]
        )
        # No target tuning or label-guided resampling is allowed.
        overlaps = sum(
            e.key() in ledger.canonical_ids or
            normalized_flow_fingerprint(e) in ledger.normalized_fingerprints
            for e in events
        )
        if overlaps:
            raise ValueError("potential exposed-source flow leakage into evaluation")
        if duplicate_rows:
            raise ValueError("duplicate IoT-23v2 flow in converted sample")
        scores = score_verified_bundle(model, events)
        measured = metrics(events, [
            SimpleNamespace(
                anomalous=bool(score >= FIXED_CUTOFF),
                anomaly_score=float(score),
            )
            for score in scores
        ])
        measured.pop("operational_gate", None)
    if digest(original) != SOURCE_SHA256 or digest(bundle_path) != FROZEN_RF_SHA256:
        raise ValueError("source or model changed during research evaluation")
    fpr_upper = measured["fpr_wilson95"][1]
    recall_lower = measured["recall_wilson95"][0]
    numeric_pass = fpr_upper <= MAX_FPR_UPPER and recall_lower >= MIN_RECALL_LOWER
    # Numeric failure is evidence, not cause to optimize against exposed labels.
    return {
        "schema_version": 1,
        "status": "completed_exposed_laboratory_family_research_no_acceptance",
        "research_only": True,
        "source_exposed_to_analyst_before_exact_runtime_confirmation": True,
        "model_untouched_from_prior_unsw_freeze": True,
        "preselected_threshold": FIXED_CUTOFF,
        "dataset_sha256": SOURCE_SHA256,
        "model_sha256": FROZEN_RF_SHA256,
        "training_ledger_sha256": frozen["training_ledger_sha256"],
        "training_flow_overlap": 0,
        "source_missingness_report": audit,
        "evaluation": measured,
        "numeric_research_gate": "passed" if numeric_pass else "failed",
        "production_ml_acceptance_demonstrated": False,
        "production_signed_model_evaluated": False,
        "independently_operated_site_audited": False,
        "independent_soc_labels_adjudicated": False,
        "fully_covered_capture": audit["excluded_missing_native_values"] == 0,
        "limitations": [
            "IoT-23v2 is another controlled research laboratory family, not a deployed SOC site.",
            "Already inspected local IoT-23v2 labels/results are exposed; not a pristine holdout.",
            "Missing sensor byte/duration values are excluded, not imputed; strong selection bias.",
            "Only complete-case scores measured: cannot infer all-flow field FPR/recall.",
            "Source capture labels are researcher provided, not independently re-adjudicated.",
            "Unsigned source RF is not an approved, active deployment model.",
            "Flow Wilson intervals ignore correlated connections/hosts.",
        ],
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iot23v2-source", type=Path, required=True)
    p.add_argument("--frozen-bundle", type=Path, required=True)
    p.add_argument("--frozen-manifest", type=Path, required=True)
    p.add_argument("--private-training-ledger", type=Path, required=True)
    p.add_argument("--aggregate-evidence", type=Path, required=True)
    a = p.parse_args()
    if a.aggregate_evidence.exists():
        p.error("refusing to overwrite research evidence")
    result = run(a.iot23v2_source, a.frozen_bundle, a.frozen_manifest,
                 a.private_training_ledger)
    a.aggregate_evidence.parent.mkdir(parents=True, exist_ok=True)
    with a.aggregate_evidence.open("x", encoding="utf-8") as out:
        json.dump(result, out, indent=2, sort_keys=True, allow_nan=False)
        out.write("\n")
    print(json.dumps({
        "status": result["status"],
        "numeric_research_gate": result["numeric_research_gate"],
        "confusion_matrix": result["evaluation"]["confusion_matrix"],
        "fpr": result["evaluation"]["fpr"],
        "recall": result["evaluation"]["recall"],
        "operational_ml_acceptance_demonstrated": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
