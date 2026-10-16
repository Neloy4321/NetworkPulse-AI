"""Strict IoT-23v2 Zeek TSV labeled-flow preparation for research ONLY.

This adapter NEVER invents missing Zeek duration, byte or packet counters.
IoT-23v2 is a controlled Stratosphere laboratory capture, not a production
site. Neither labels nor outcomes are used for model selection or training.
Do not publish raw flow rows, IPs, UIDs, or hashes that expose identifiers.

The _legacy_ 2018 IoT-23 capture README notes authorization is needed,
whereas Stratosphere's general dataset FAQ permits cited research use.
Verify applicable permissions for the specific downloaded distribution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from networkpulse.schemas import FlowEvent

REGISTERED_CAPTURE = "CTU-IoT-Malware-Capture-34-1"
DATASET_FAMILY = "IoT-23v2"
SOURCE_URL = (
    "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/"
    "CTU-IoT-Malware-Capture-34-1/"
    "2018-12-21-15-50-14-192.168.1.195-zeek-conn-log.labeled"
)
COLUMNS = (
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp", "missed_bytes",
    "history", "orig_pkts", "orig_ip_bytes", "resp_pkts",
    "resp_ip_bytes",
)
TRAILER = "tunnel_parents   label   detailed-label"
MIN_BENIGN = 200
MIN_ATTACK = 100
MAX_ROWS = 300_000
MAX_ROW_CHARS = 32_768


class MissingNativeFeature(ValueError):
    """Flow cannot be scored without misrepresenting the sensor record."""


def _required_number(raw: str, *, integer: bool):
    if raw in ("-", "(empty)", "", "(unset)"):
        raise MissingNativeFeature("required sensor measurement is absent")
    try:
        num = int(raw) if integer else float(raw)
    except (ValueError, OverflowError) as exc:
        raise ValueError("non-numeric native feature") from exc
    if not math.isfinite(num) or num < 0:
        raise ValueError("non-finite/negative native feature")
    return num


def _require_header(raw: str) -> None:
    if not raw.startswith("#fields\t"):
        raise ValueError("official Zeek #fields header is required")
    fields = raw.rstrip("\r\n").split("\t")[1:]
    if len(fields) != 21 or tuple(fields[:20]) != COLUMNS or fields[20] != TRAILER:
        raise ValueError("unknown IoT-23v2 conn.log labeled schema: fail closed")


def parse_labeled_line(raw: str) -> FlowEvent:
    """Parse v2 Zeek TSV with the three-space joined trailing label cells."""
    if len(raw) > MAX_ROW_CHARS:
        raise ValueError("oversized Zeek flow row")
    parts = raw.rstrip("\r\n").split("\t")
    if len(parts) != 21:
        raise ValueError("wrong Zeek source column count")
    trailing = re.split(r"\s{2,}", parts[20].strip())
    if len(trailing) != 3:
        raise ValueError("missing independent label trailer")
    label = trailing[1]
    if label not in ("Benign", "Malicious"):
        raise ValueError("unsupported or ambiguous IoT-23 label")
    proto_raw = parts[6].strip().lower()
    protocol = proto_raw if proto_raw in ("tcp", "udp", "icmp") else "other"
    # Original source values are mandatory; '-' is NOT zero.
    return FlowEvent(
        timestamp=datetime.fromtimestamp(
            _required_number(parts[0], integer=False), timezone.utc
        ),
        source="zeek",
        uid=parts[1],
        src_ip=parts[2],
        src_port=_required_number(parts[3], integer=True),
        dst_ip=parts[4],
        dst_port=_required_number(parts[5], integer=True),
        proto=protocol,
        duration=_required_number(parts[8], integer=False),
        orig_bytes=_required_number(parts[9], integer=True),
        resp_bytes=_required_number(parts[10], integer=True),
        conn_state=parts[11],
        orig_pkts=_required_number(parts[16], integer=True),
        resp_pkts=_required_number(parts[18], integer=True),
        label="benign" if label == "Benign" else "anomaly",
    )


def inspect_and_convert(source: Path, output: Path, report: Path) -> dict:
    """Convert only supported authentic rows, retain missingness counts.

    Cannot certify independent-site or operational acceptance. Only a separate
    external model scorer with pinned model/ledger may evaluate the output.
    """
    if output.exists() or report.exists():
        raise ValueError("refusing overwrite of immutable external-data evidence")
    if not source.is_file():
        raise ValueError("source log not present")
    if source.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("single registered capture exceeds approved size")
    digest = hashlib.sha256()
    scanned = Counter()
    written = Counter()
    temp = output.with_name(output.name + ".partial")
    if temp.exists():
        raise ValueError("leftover private partial output")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with source.open("rb") as stream, temp.open("x", encoding="utf-8") as dest:
            fields_seen = False
            for lineno, raw_bytes in enumerate(stream, 1):
                digest.update(raw_bytes)
                if len(raw_bytes) > MAX_ROW_CHARS:
                    raise ValueError("oversized Zeek source line")
                try:
                    raw = raw_bytes.decode("utf-8")
                except UnicodeError as exc:
                    raise ValueError("invalid UTF-8 Zeek input") from exc
                if raw.startswith("#fields\t"):
                    _require_header(raw)
                    fields_seen = True
                    continue
                if raw.startswith("#"):
                    continue
                if not fields_seen:
                    raise ValueError("first data flow encountered before #fields")
                if sum(scanned.values()) >= MAX_ROWS:
                    raise ValueError("input exceeds predeclared source row budget")
                try:
                    event = parse_labeled_line(raw)
                except MissingNativeFeature:
                    scanned["missing_native_features"] += 1
                    continue
                except Exception as exc:
                    raise ValueError("invalid labeled Zeek source record at line " +
                                     str(lineno)) from exc
                written[event.label] += 1
                scanned["valid"] += 1
                dest.write(event.model_dump_json() + "\n")
        if not fields_seen:
            raise ValueError("no strict Zeek #fields schema found")
        if written["benign"] < MIN_BENIGN or written["anomaly"] < MIN_ATTACK:
            raise ValueError("natural source class coverage insufficient")
        total = scanned["valid"] + scanned["missing_native_features"]
        excluded_rate = scanned["missing_native_features"] / total
        evidence = {
            "status": "iot23v2_schema_conversion_only",
            "dataset_family": DATASET_FAMILY,
            "capture": REGISTERED_CAPTURE,
            "source_url": SOURCE_URL,
            "source_sha256": digest.hexdigest(),
            "source_bytes": source.stat().st_size,
            "source_rows_total": total,
            "converted_labeled_rows": scanned["valid"],
            "excluded_missing_native_values": scanned["missing_native_features"],
            "excluded_fraction": round(excluded_rate, 6),
            "benign_complete_rows": written["benign"],
            "attack_complete_rows": written["anomaly"],
            "sensor_missing_values_were_imputed": False,
            "source_labels_used_for_training": False,
            "site_independence_verified": False,
            "operational_ml_acceptance_demonstrated": False,
            "unsupported_capture_data_selection": False,
            "warning": (
                "Missingness may depend on label and sensor state; even a numerical "
                "PASS on the complete-case subset cannot establish full-capture "
                "or independent-site operational acceptance."
            ),
        }
        output_sha = hashlib.sha256(temp.read_bytes()).hexdigest()
        evidence["canonical_sha256"] = output_sha
        if report.exists():
            raise ValueError("report already exists")
        with report.open("x", encoding="utf-8") as out:
            json.dump(evidence, out, sort_keys=True, indent=2, allow_nan=False)
            out.write("\n")
        temp.replace(output)
        return evidence
    except Exception:
        temp.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original-zeek", type=Path, required=True)
    parser.add_argument("--private-canonical", type=Path, required=True)
    parser.add_argument("--aggregate-report", type=Path, required=True)
    args = parser.parse_args()
    result = inspect_and_convert(
        args.original_zeek, args.private_canonical, args.aggregate_report
    )
    print(json.dumps({
        "status": result["status"],
        "source_rows": result["source_rows_total"],
        "converted": result["converted_labeled_rows"],
        "omitted_missing": result["excluded_missing_native_values"],
        "operational_ml_acceptance_demonstrated": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
