"""Verify signed staging evidence integrity; never certify production itself."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from networkpulse.deployment_evidence import verify_deployment_evidence
from networkpulse.generalization_evidence import write_evidence_once


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--external-report", type=Path, required=True)
    p.add_argument("--staging-report", type=Path, required=True)
    p.add_argument("--operator-attestation", type=Path, required=True)
    p.add_argument("--detached-signature", type=Path, required=True)
    p.add_argument("--trusted-public-key", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args(argv)
    if a.report.exists():
        p.error("Evidence output already exists")
    result = verify_deployment_evidence(
        external_report=a.external_report, staging_report=a.staging_report,
        attestation_file=a.operator_attestation,
        signature_file=a.detached_signature,
        public_key_file=a.trusted_public_key,
    )
    write_evidence_once(a.report, result)
    print(json.dumps({"status": result["status"],
                      "production_certified": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
