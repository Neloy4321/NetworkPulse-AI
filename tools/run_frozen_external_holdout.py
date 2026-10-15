"""Run a signed frozen NetworkPulse detector against approved external holdout.

Exits 0 only on pre-registered confidence-bound and capture-day acceptance.
This tool does not create a model or turn CI traffic into production evidence.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from networkpulse.adapters import iter_jsonl
from networkpulse.deployment_preflight import verify_deployment_model
from networkpulse.detector import Detector
from networkpulse.generalization_evidence import (
    ExternalHoldoutSpec, evaluate_frozen_holdout, load_training_keys,
    verify_training_source_ledger, write_evidence_once,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--holdout", type=Path, required=True,
                        help="Original labeled canonical JSONL real external corpus")
    parser.add_argument("--spec", type=Path, required=True,
                        help="Pre-registered, reviewed external-domain acceptance spec JSON")
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--registry-root", type=Path, required=True,
                        help="Signed approved release registry root")
    parser.add_argument("--original-training-corpus", type=Path, required=True,
                        help="Exact pinned training-domain corpus; securely handled")
    parser.add_argument("--training-event-ids", type=Path, required=True,
                        help="Training corpus canonical IDs, one 32-hex ID per line")
    parser.add_argument("--training-event-ids-sha256", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.report.exists():
        parser.error("Immutable evidence output already exists")
    spec = ExternalHoldoutSpec.from_json(args.spec)
    # Verify the signed ACTIVE model before any joblib pickle deserialization.
    verified = verify_deployment_model(
        model_path=args.model, expected_sha256=spec.model_sha256,
        registry_root=args.registry_root,
    )
    if verified.get("sha256") != spec.model_sha256:
        raise ValueError("Signed registry verified another model SHA256")
    training_keys = load_training_keys(
        args.training_event_ids, args.training_event_ids_sha256,
    )
    verify_training_source_ledger(
        args.original_training_corpus, spec.training_sha256,
        args.training_event_ids_sha256,
    )
    try:
        report = evaluate_frozen_holdout(
            spec=spec, model_path=args.model, corpus_path=args.holdout,
            records_factory=lambda: iter_jsonl(args.holdout, "canonical"),
            detector_loader=Detector.load, training_keys=training_keys,
        )
    except Exception as exc:
        report = {
            "schema_version": 1, "status": "failed",
            "scope": "frozen_cross_domain_labeled_holdout_not_field_certification",
            "failure_type": type(exc).__name__,
            "model_sha256": spec.model_sha256,
            "holdout_sha256": spec.holdout_sha256,
            "note": "No validation claim; inspect private operator logs for details",
        }
    write_evidence_once(args.report, report)
    print(json.dumps({k: report.get(k) for k in (
        "status", "scope", "unique_holdout_events", "false_positive_rate",
        "recall", "average_precision", "failure_type") if k in report}, sort_keys=True))
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
