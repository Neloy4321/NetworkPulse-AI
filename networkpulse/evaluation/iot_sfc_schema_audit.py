"""Read only the bounded CSV header of the SHA-pinned IoT-SFC v2 ZIP.

No flow rows, label values, model deserialization, training, inference, or
operational approval. Only use this tool on a legitimately obtained local file.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import stat
import zipfile
from pathlib import Path

from networkpulse.evaluation.iot_sfc_preregistration import (
    MODEL_SHA, PROTOCOL, TARGET_SHA, TARGET_SIZE, validate_preregistration,
)

CSV_MEMBER = "iot_dataset_v7.csv"
MAX_HEADER_BYTES = 131072
EXPECTED_PUBLISHER_COLUMNS = 87
# Exact Zeek conn.log names, not inferred application log equivalents.
REQUIRED_ZEEK_CONN = (
    "ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
)
OPTIONAL_ZEEK_CONN = (
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "conn_state",
)
SOURCE_LOG_FIELDS = (
    "log_type", "log_source", "source_log", "zeek_log", "log_name", "_path",
)
LABEL_FIELDS = ("label", "attack_label", "is_attack", "type_of_attack")
# These *might* be aliases; no automatic mapping from a merged record.
POTENTIAL_ALIASES = {
    "ts": ("timestamp", "time", "start_time"),
    "id.orig_h": ("src_ip", "source_ip", "orig_h"),
    "id.orig_p": ("src_port", "source_port", "orig_p"),
    "id.resp_h": ("dst_ip", "dest_ip", "destination_ip", "resp_h"),
    "id.resp_p": ("dst_port", "dest_port", "destination_port", "resp_p"),
    "proto": ("protocol",),
}
EXPECTED_ARCHIVE_MD5 = "6b858e337a8241b89f4d76f9a1454a60"


def _digest(path: Path) -> tuple[str, str]:
    sha = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(4 * 1024 * 1024), b""):
            sha.update(chunk)
            md5.update(chunk)
    return sha.hexdigest(), md5.hexdigest()


def _canonical_columns(header: bytes) -> list[str]:
    if not header or len(header) > MAX_HEADER_BYTES:
        raise ValueError("Missing or excessive CSV header")
    if b"\x00" in header or not header.endswith(b"\n"):
        raise ValueError("CSV header must be bounded, newline terminated, and text only")
    decoded = header.decode("utf-8-sig", errors="strict")
    # A quoted newline in a column name cannot be safely interpreted by this
    # header-only reader: never continue into private data to guess its ending.
    if decoded.count("\n") != 1 or "\r" in decoded[:-2]:
        raise ValueError("Multiline or malformed CSV header is unsupported")
    parsed = list(csv.reader([decoded], strict=True))
    if len(parsed) != 1:
        raise ValueError("Exactly one CSV header row required")
    columns = [col.strip() for col in parsed[0]]
    if not 1 <= len(columns) <= 1024 or any(
        not col or len(col) > 200 or not re.fullmatch(r"[\w. \-/]+", col)
        for col in columns
    ):
        raise ValueError("Unexpected, empty or unsafe column names")
    if len(set(columns)) != len(columns):
        raise ValueError("Duplicate CSV column names")
    return columns


def classify_header(columns: list[str]) -> dict:
    present = set(columns)
    casefold = {name.casefold(): name for name in columns}
    exact = [key for key in REQUIRED_ZEEK_CONN if key in present]
    missing = [key for key in REQUIRED_ZEEK_CONN if key not in present]
    aliases = {
        name: [casefold[v] for v in alternatives if v in casefold]
        for name, alternatives in POTENTIAL_ALIASES.items() if name in missing
    }
    log_source = [name for name in SOURCE_LOG_FIELDS if name in present]
    labels = [name for name in LABEL_FIELDS if name in present]
    # Schema naming alone never proves direction, conn.log provenance, labels
    # or timestamp semantics. Thus "numeric eligible" is never granted here.
    blocked = (
        bool(missing) or not log_source or not labels
        or len(columns) != EXPECTED_PUBLISHER_COLUMNS
    )
    return {
        "column_count": len(columns),
        "publisher_expected_column_count": EXPECTED_PUBLISHER_COLUMNS,
        "columns": columns,
        "required_zeek_conn_exact_present": exact,
        "required_zeek_conn_missing": missing,
        "possible_unverified_aliases": aliases,
        "optional_zeek_conn_present": [
            name for name in OPTIONAL_ZEEK_CONN if name in present
        ],
        "possible_log_source_columns": log_source,
        "possible_label_columns": labels,
        "header_only_schema_status": (
            "BLOCKED_REQUIRES_EXPLICIT_SENSOR_ADAPTER_REVIEW"
            if blocked else "HEADER_FIELDS_PRESENT_ROW_SEMANTICS_UNVERIFIED"
        ),
        "conn_log_row_filter_verified": False,
        "flow_direction_semantics_verified": False,
        "per_flow_labels_verified": False,
        "no_application_log_row_scored_as_flow": True,
        "accepted_for_model_scoring": False,
    }


def audit_archive(path: Path, *, preregistration: Path = PROTOCOL) -> dict:
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("Refusing nonregular or symlink archive")
    if path.name != "iot_dataset_v7.zip" or path.stat().st_size != TARGET_SIZE:
        raise ValueError("Incorrect archive name or byte length")
    spec = json.loads(preregistration.read_text(encoding="utf-8"))
    validate_preregistration(spec)
    if (spec["model"]["artifact_sha256"] != MODEL_SHA
            or spec["model"]["threshold"] != 0.2
            or spec["target"]["archive_sha256"] != TARGET_SHA):
        raise ValueError("Frozen model/threshold/target identity was changed")

    digest, md5 = _digest(path)
    if digest != TARGET_SHA or md5 != EXPECTED_ARCHIVE_MD5:
        raise ValueError("Local archive differs from preregistered original bytes")

    with zipfile.ZipFile(path, "r", allowZip64=True) as zf:
        items = zf.infolist()
        if len(items) != 1:
            raise ValueError("One and only one preregistered CSV member expected")
        member = items[0]
        if (member.filename != CSV_MEMBER or member.is_dir()
                or member.flag_bits & 1 or member.file_size != 13561863941
                or member.compress_type != zipfile.ZIP_DEFLATED
                or member.external_attr >> 16 & 0o170000 == 0o120000):
            raise ValueError("Unexpected, encrypted, symlinked or altered ZIP member")
        with zf.open(member, "r") as stream:
            # NEVER read a full row or the uncompressed 13.56 GB member.
            header = stream.readline(MAX_HEADER_BYTES + 1)
    columns = _canonical_columns(header)
    return {
        "schema_version": 1,
        "status": "HEADER_ONLY_AUDIT_COMPLETED_NOT_READY_FOR_SCORING",
        "dataset_version": "iot-sfc-v2-zenodo-23371775",
        "archive_sha256_verified_from_original_bytes": True,
        "archive_md5_verified_from_original_bytes": True,
        "archive_sha256": digest,
        "archive_bytes": TARGET_SIZE,
        "model_artifact_sha256_unchanged": MODEL_SHA,
        "frozen_threshold_unchanged": 0.2,
        "feature_contract": "missingness_aware_flow_v2",
        "csv_header_read": True,
        "csv_data_rows_read": False,
        "label_values_read": False,
        "model_predictions_generated": False,
        "member_crc_verified": False,
        "legal_reuse_rights_confirmed": False,
        "dataset_ground_truth_verified": False,
        "independent_field_site": False,
        "operational_ml_acceptance": "NO_GO",
        "schema": classify_header(columns),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--preregistration", type=Path, default=PROTOCOL)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists() or args.report.is_symlink():
        parser.error("Refusing to overwrite audit evidence")
    result = audit_archive(args.archive, preregistration=args.preregistration)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.report, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as dest:
        json.dump(result, dest, sort_keys=True, indent=2, allow_nan=False)
        dest.write("\n")
    print(json.dumps({
        "status": result["status"],
        "schema": result["schema"]["header_only_schema_status"],
        "row_or_labels_examined": False,
        "operational_ml_acceptance": "NO_GO",
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
