"""Bounded REAL IoT-SFC v7 source/label metadata audit, before any scoring.

This is a controlled unblinding of a preregistered target for provenance
qualification, NOT training, target-guided calibration or ML acceptance.
Original raw rows and identifying fields NEVER leave the ephemeral runner.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import stat
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from networkpulse.evaluation.iot_sfc_preregistration import (
    MODEL_SHA, TARGET_SHA, TARGET_SIZE,
)
from networkpulse.evaluation.iot_sfc_v7_conn_adapter import (
    HEADER_EVIDENCE, RowNotEligible, conn_log_to_flow_v2,
    inspect_untrusted_producer_label, verify_exact_header,
)

ZIP_MEMBER = "iot_dataset_v7.csv"
MAX_SAMPLE_ROWS = 200_000
DEFAULT_SAMPLE_ROWS = 100_000
FIELD_MAX_CHARS = 131_072
KNOWN_LOG_TYPES = frozenset({
    "conn.log", "dns.log", "http.log", "ssl.log", "ssh.log", "weird.log",
    "files.log", "mqtt_connect.log", "mqtt_publish.log",
    "mqtt_subscribe.log", "mqtt_disconnect.log",
})
LABEL_CATEGORIES = {"0", "1"}
MISSING = frozenset({"", "-", "(empty)", "(unset)"})


def _sha256_archive(path: Path) -> str:
    if path.name != "iot_dataset_v7.zip" or path.is_symlink():
        raise ValueError("Archive identity or symlink rejected")
    if not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size != TARGET_SIZE:
        raise ValueError("Original archive byte length or file type mismatch")
    h = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    value = h.hexdigest()
    if value != TARGET_SHA:
        raise ValueError("Archive not equal to preregistered original SHA")
    return value


def _present(value: object) -> bool:
    return value is not None and str(value).strip() not in MISSING


def _classify_log_type(value: object) -> str:
    value = str(value).strip() if value is not None else ""
    return value if value in KNOWN_LOG_TYPES else "UNRECOGNIZED_OR_MISSING"


def _classify_binary(value: object) -> str:
    value = str(value).strip() if value is not None else ""
    return value if value in LABEL_CATEGORIES else "NOT_LITERAL_BINARY_0_OR_1"


def summarize_rows(rows, *, max_rows: int = DEFAULT_SAMPLE_ROWS) -> dict:
    """A bounded FIRST-N sample, NOT a random/full dataset sample.

    Never put raw row values, IPs, UIDs, source tokens or attack names in
    outputs. Counts only. No predictor/model object is used.
    """
    if not isinstance(max_rows, int) or not 1 <= max_rows <= MAX_SAMPLE_ROWS:
        raise ValueError("Sample size outside predeclared safe bound")
    counts = Counter()
    logs = Counter()
    all_binary = Counter()
    conn_binary = Counter()
    conn_adapter_status = Counter()
    conn_producer_status = Counter()
    capture_days = Counter()
    missing_numeric = Counter()
    processed = 0
    for row in rows:
        if processed >= max_rows:
            break
        processed += 1
        if not isinstance(row, dict) or any(k is None for k in row):
            counts["invalid_row_column_count"] += 1
            continue
        # Do not log or persist ANY raw value, including unknown log_type.
        log_type = _classify_log_type(row.get("log_type"))
        logs[log_type] += 1
        label_kind = _classify_binary(row.get("attack"))
        all_binary[label_kind] += 1
        if log_type != "conn.log":
            counts["not_exact_conn_log"] += 1
            continue
        counts["candidate_exact_conn_log"] += 1
        conn_binary[label_kind] += 1
        try:
            flow = conn_log_to_flow_v2(row)
        except RowNotEligible as exc:
            # Error codes are fixed in the versioned adapter; no user row.
            error = str(exc)
            if error not in {
                "missing_required_column", "missing_required_identity",
                "ambiguous_mixed_native_and_merged_columns",
                "invalid_native_zeek_conn_values", "not_explicit_conn_log",
                "target_label_leaked_into_inference",
            }:
                error = "UNKNOWN_REJECTION"
            conn_adapter_status[error] += 1
            continue
        conn_adapter_status["FLOW_V2_CANDIDATE_VALID"] += 1
        # Capture day is aggregate (no timestamps or sensor IDs in artifacts).
        capture_days[flow.timestamp.date().isoformat()] += 1
        for col in ("duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"):
            if getattr(flow, col) is None:
                missing_numeric[col] += 1
        try:
            evidence = inspect_untrusted_producer_label(row)
        except RowNotEligible as exc:
            code = str(exc)
            if code not in {
                "missing_producer_label_columns", "invalid_binary_producer_label",
                "missing_attack_provenance_fields",
            }:
                code = "UNKNOWN_LABEL_REJECTION"
            conn_producer_status[code] += 1
        else:
            conn_producer_status[
                "PRODUCER_0_UNVERIFIED" if evidence.producer_class == 0
                else "PRODUCER_1_UNVERIFIED"
            ] += 1
            if not evidence.label_source_present:
                conn_producer_status["missing_label_source"] += 1
            if not evidence.window_id_present:
                conn_producer_status["missing_window_id"] += 1

    total = sum(logs.values())
    if processed != total + counts["invalid_row_column_count"]:
        raise AssertionError("Internal audited-row accounting error")
    return {
        "sample_strategy": "FIRST_N_IN_ARCHIVE_ORDER_NONREPRESENTATIVE",
        "requested_max_rows": max_rows,
        "rows_inspected": processed,
        "row_values_recorded_or_exported": False,
        "raw_addresses_or_uids_recorded": False,
        "log_types_aggregate": dict(sorted(logs.items())),
        "source_binary_label_literals_aggregate": dict(sorted(all_binary.items())),
        "conn_only_binary_label_literals_aggregate": dict(sorted(conn_binary.items())),
        "conn_adapter_outcomes": dict(sorted(conn_adapter_status.items())),
        "producer_label_outcomes_unverified": dict(sorted(conn_producer_status.items())),
        "eligible_candidate_capture_days_aggregate": dict(sorted(capture_days.items())),
        "candidate_missing_counter_counts": dict(sorted(missing_numeric.items())),
        "invalid_row_column_count": counts["invalid_row_column_count"],
        "not_exact_conn_log_count": counts["not_exact_conn_log"],
        "not_an_unbiased_dataset_prevalence_estimate": True,
        "labels_independently_adjudicated": False,
        "model_training_or_inference_performed": False,
        "numerical_ml_acceptance_calculated": False,
    }


def audit_archive(path: Path, *, max_rows: int = DEFAULT_SAMPLE_ROWS) -> dict:
    digest = _sha256_archive(path)
    with zipfile.ZipFile(path, "r", allowZip64=True) as zipped:
        members = zipped.infolist()
        if len(members) != 1:
            raise ValueError("Expected one original CSV ZIP member")
        member = members[0]
        if (member.filename != ZIP_MEMBER or member.is_dir() or member.flag_bits & 1
                or member.file_size != 13_561_863_941
                or member.compress_type != zipfile.ZIP_DEFLATED):
            raise ValueError("ZIP content identity or encryption mismatch")
        with zipped.open(member) as raw:
            with io.TextIOWrapper(raw, encoding="utf-8-sig", newline="") as handle:
                prior_limit = csv.field_size_limit()
                csv.field_size_limit(FIELD_MAX_CHARS)
                try:
                    reader = csv.reader(handle, strict=True)
                    header = next(reader)
                    verify_exact_header(header)
                    def row_iter():
                        for cells in reader:
                            if len(cells) != len(header):
                                yield {None: "mismatched_row_width"}
                            else:
                                yield dict(zip(header, cells))
                    metrics = summarize_rows(row_iter(), max_rows=max_rows)
                finally:
                    csv.field_size_limit(prior_limit)
    return {
        "schema_version": 1,
        "audit_status": "BOUNDED_REAL_SOURCE_PROVENANCE_INSPECTED_NO_MODEL_SCORE",
        "dataset": "IoT-SFC v7 / Zenodo 23371775",
        "original_archive_sha256": digest,
        "original_archive_bytes": TARGET_SIZE,
        "frozen_unsigned_research_model_sha256": MODEL_SHA,
        "frozen_threshold": 0.20,
        "feature_contract": "missingness_aware_flow_v2",
        "dataset_permission_basis": "USER_REPORTED_RESEARCH_USE_WITH_CITATION_REQUIRED",
        "permission_document_not_independently_verified": True,
        "dataset_citation": "https://zenodo.org/records/23371775",
        "csv_full_payload_crc_checked": False,
        "full_dataset_scanned": False,
        "target_label_values_inspected": True,
        "target_now_partially_unblinded_for_provenance": True,
        "target_labels_used_to_fit_tune_or_select_model": False,
        "reviewed_ground_truth": False,
        "field_site_operator_independent": False,
        "model_scored": False,
        "operational_ml_acceptance": "NO_GO",
        "aggregate": metrics,
        "next_gate": (
            "Independent source log/label semantics, provenance and leakage "
            "audit before any frozen research-only scoring"
        ),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--max-rows", type=int, default=DEFAULT_SAMPLE_ROWS)
    p.add_argument("--report", type=Path, required=True)
    args = p.parse_args()
    if args.report.exists() or args.report.is_symlink():
        p.error("Will not overwrite evidence")
    report = audit_archive(args.archive, max_rows=args.max_rows)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as dest:
        json.dump(report, dest, sort_keys=True, indent=2, allow_nan=False)
        dest.write("\n")
        dest.flush()
        os.fsync(dest.fileno())
    print(json.dumps({
        "audit_status": report["audit_status"],
        "rows_inspected": report["aggregate"]["rows_inspected"],
        "model_scored": False, "operational_ml_acceptance": "NO_GO",
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
