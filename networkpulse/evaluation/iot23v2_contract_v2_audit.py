"""Evaluate the V2 feature contract across ALL labeled IoT-23v2 source rows.

This is a DATA-CONTRACT AUDIT ONLY, not a trained model or acceptance score.
An absent counter is represented as None with an explicit feature mask, not
fabricated zero. Raw host IPs, ports, flow UIDs and row-level vectors are
not persisted. The entire dataset is already exposed research evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from networkpulse.evaluation.iot23v2_exact_runtime_recheck import (
    SOURCE_BYTES, SOURCE_SHA256,
)
from networkpulse.evaluation.iot23v2_source_adapter import (
    COLUMNS, DATASET_FAMILY, REGISTERED_CAPTURE, _require_header,
)
from networkpulse.feature_contract_v2 import (
    V2_FEATURE_CONTRACT, features_v2, from_zeek_v2,
)
from networkpulse.evaluation.unsw_to_toniot import digest

MISSING = ("duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts")


def run(path: Path) -> dict:
    if path.stat().st_size != SOURCE_BYTES or digest(path) != SOURCE_SHA256:
        raise ValueError("registered IoT-23v2 file SHA-256 or size mismatch")
    counts: Counter[str] = Counter()
    missing: Counter[str] = Counter()
    detail: Counter[str] = Counter()
    invalid = 0
    schema_seen = False
    feature_keys = set()
    seen = hashlib.sha256()
    with path.open("rb") as stream:
        for line_no, encoded in enumerate(stream, 1):
            seen.update(encoded)
            if len(encoded) > 32768:
                raise ValueError("overlong Zeek line")
            line = encoded.decode("utf-8")
            if line.startswith("#fields\t"):
                _require_header(line)
                schema_seen = True
                continue
            if line.startswith("#"):
                continue
            if not schema_seen:
                raise ValueError("Zeek schema header missing")
            columns = line.rstrip("\r\n").split("\t")
            if len(columns) != 21:
                raise ValueError("unexpected official Zeek tabular record width")
            bits = re.split(r"\s{2,}", columns[20].strip())
            if len(bits) != 3 or bits[1] not in ("Benign", "Malicious"):
                raise ValueError("ambiguous Zeek source supervision label")
            row = dict(zip(COLUMNS, columns[:20]))
            # A versioned sensor-aware feature path, not the legacy v1
            # adapter that coerces missing network observations to zero.
            try:
                event = from_zeek_v2(row)
                vectors = features_v2(event)
            except Exception as exc:
                invalid += 1
                raise ValueError("unsupported raw Zeek measurement at line " +
                                 str(line_no)) from exc
            if event.label is not None:
                raise ValueError("sensor features cannot contain training label")
            if not all(key.startswith(("log_", "missing_", "port_class=", "proto="))
                       or key == "response_fraction" for key in vectors):
                raise ValueError("unregistered v2 model feature key")
            feature_keys.update(vectors)
            counts[bits[1].lower()] += 1
            # Only bounded known benign/attack categories, no arbitrary metadata.
            if bits[2] in ("C&C", "DDoS", "PartOfAHorizontalPortScan"):
                detail[bits[2]] += 1
            for name in MISSING:
                if getattr(event, name) is None:
                    missing[name] += 1
            if any(getattr(event, name) is None for name in MISSING):
                counts["rows_with_missing_sensor_values"] += 1
            else:
                counts["fully_observed"] += 1
    if not schema_seen or seen.hexdigest() != SOURCE_SHA256:
        raise ValueError("real source schema or integrity changed during read")
    total = counts["benign"] + counts["malicious"]
    if total != 23145 or counts["benign"] != 1923 or counts["malicious"] != 21222:
        raise ValueError("registered research capture natural row support changed")
    if invalid:
        raise ValueError("cannot declare entire source supported with malformed rows")
    if len(feature_keys) < 18:
        raise ValueError("missingness-aware versioned feature coverage incomplete")
    return {
        "status": "iot23v2_full_capture_v2_feature_compatibility_verified",
        "schema_version": 1,
        "feature_contract": V2_FEATURE_CONTRACT,
        "pinned_source_sha256": SOURCE_SHA256,
        "original_labeled_records": total,
        "benign_records": counts["benign"],
        "malicious_records": counts["malicious"],
        "v2_parsed_and_vectorized": total,
        "v2_rows_rejected": 0,
        "v2_rows_with_missing_measurements": counts["rows_with_missing_sensor_values"],
        "legacy_v1_fully_observed_subset": counts["fully_observed"],
        "individual_missing_counts": dict(missing),
        "registered_feature_keys": len(feature_keys),
        "missing_measurements_never_converted_to_measured_zero": True,
        "target_label_used_in_model_feature": False,
        "source_family": DATASET_FAMILY,
        "capture_id": REGISTERED_CAPTURE,
        "model_trained": False,
        "production_signed_model_deployed": False,
        "p0_operational_ml_acceptance": "NO_GO",
        "warning": (
            "Full source compatibility only; a newly trained v2 model is "
            "required, plus independent field data and production equivalence."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iot23v2-labeled", type=Path, required=True)
    parser.add_argument("--aggregate-report", type=Path, required=True)
    args = parser.parse_args()
    if args.aggregate_report.exists():
        parser.error("refuse overwriting source contract evidence")
    result = run(args.iot23v2_labeled)
    args.aggregate_report.parent.mkdir(parents=True, exist_ok=True)
    with args.aggregate_report.open("x", encoding="utf-8") as file:
        json.dump(result, file, indent=2, sort_keys=True, allow_nan=False)
        file.write("\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
