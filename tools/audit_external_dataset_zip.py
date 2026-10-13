"""Inspect large, publicly shared Google Drive dataset archives on ephemeral CI.

Reads member filenames and bounded header samples; never extracts full archives,
loads packet payloads, or commits source data. Produces a compact JSON manifest.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import sys
import tempfile
import time
import zipfile
from collections import Counter
from pathlib import Path

MAX_HEADER_BYTES = 32768
MAX_SAMPLE_FILES = 35
MAX_LISTED_ENTRIES = 2000


def dataset_hints(paths: list[str], headers: list[list[str]]) -> list[dict]:
    names = " ".join(paths).lower()
    normalized_headers = [{str(k).strip().lower() for k in row} for row in headers]
    hints = []

    def add(name, reason):
        hints.append({"dataset_family": name, "evidence": reason})

    if "unsw_nb15" in names or "unsw-nb15" in names or any(
        {"attack_cat", "sbytes", "dbytes", "spkts", "dpkts"} <= x for x in normalized_headers
    ):
        add("UNSW-NB15", "UNSW filename or attack_cat + UNSW flow features")
    if "machinelearningcve" in names or "friday-workinghours" in names or "monday-workinghours" in names or any(
        {"flow duration", "total fwd packets", "total backward packets", "label"} <= x for x in normalized_headers
    ):
        add("CIC-IDS2017 CICFlowMeter", "CIC-IDS2017 day file or CICFlowMeter columns")
    if "trafficforml_cicflowmeter" in names or "cse-cic-ids2018" in names:
        add("CSE-CIC-IDS2018", "CSE-CIC-IDS2018 flow CSV naming")
    if "cicddos2019" in names or "cic-ddos2019" in names:
        add("CIC-DDoS2019", "archive path")
    if "ton_iot" in names or "ton-iot" in names or "toniot" in names:
        add("TON_IoT", "archive path")
    if "nsl-kdd" in names or "kddtrain" in names or "kddtest" in names:
        add("NSL-KDD", "archive path")
    if "zeek" in names or "conn.log" in names:
        add("Zeek logs", "sensor log filename")
    if "eve.json" in names or "suricata" in names:
        add("Suricata EVE", "sensor log filename")
    if not hints:
        add("Undetermined", "No identifying filenames or sampled schema")
    return hints


def _decode_header(zf: zipfile.ZipFile, item: zipfile.ZipInfo):
    if item.file_size > 100_000_000_000:
        return {"file": item.filename, "error": "declared size > 100 GB; skipped"}
    try:
        with zf.open(item) as member:
            start = member.read(MAX_HEADER_BYTES)
        if not start:
            return {"file": item.filename, "columns": []}
        content = start.decode("utf-8-sig", errors="replace")
        row = next(csv.reader(io.StringIO(content)), [])
        return {
            "file": item.filename,
            "columns": [c.strip() for c in row[:160]],
            "column_count_sampled": len(row),
            "size_bytes": item.file_size,
        }
    except Exception as exc:
        return {"file": item.filename, "error": type(exc).__name__ + ": " + str(exc)[:140]}


def inspect_zip(path: Path, *, archive_label: str, drive_file_id: str):
    started = time.monotonic()
    with zipfile.ZipFile(path, allowZip64=True) as zf:
        entries = zf.infolist()
        files = [v for v in entries if not v.is_dir()]
        types = Counter(Path(v.filename).suffix.lower() or "[none]" for v in files)
        csv_entries = [v for v in files if v.filename.lower().endswith((".csv", ".tsv"))]
        csv_entries.sort(key=lambda v: (-v.file_size, v.filename.lower()))
        samples = [_decode_header(zf, v) for v in csv_entries[:MAX_SAMPLE_FILES]]
        result = {
            "archive": archive_label,
            "drive_file_id_suffix": drive_file_id[-6:],
            "status": "inspected",
            "zip_bytes": path.stat().st_size,
            "entry_count": len(entries),
            "file_count": len(files),
            "extensions": dict(types.most_common()),
            "uncompressed_total_bytes_declared": sum(v.file_size for v in files),
            "compressed_total_bytes_declared": sum(v.compress_size for v in files),
            "dataset_hints": dataset_hints(
                [v.filename for v in files], [x["columns"] for x in samples if "columns" in x]
            ),
            "file_list": [
                {"path": v.filename, "uncompressed_bytes": v.file_size,
                 "compressed_bytes": v.compress_size}
                for v in files[:MAX_LISTED_ENTRIES]
            ],
            "file_list_truncated": len(files) > MAX_LISTED_ENTRIES,
            "csv_header_samples": samples,
            "seconds_to_inspect": round(time.monotonic() - started, 2),
        }
        return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--expected-bytes", type=int, required=True)
    parser.add_argument("--report-dir", default="archive-audit-reports")
    args = parser.parse_args()
    out = Path(args.report_dir)
    out.mkdir(parents=True, exist_ok=True)
    report = out / (args.label + ".json")
    result = {"archive": args.label, "status": "not_checked"}
    try:
        import gdown
        with tempfile.TemporaryDirectory(prefix="networkpulse-zip-") as temp:
            path = Path(temp) / "dataset.zip"
            print(f"Starting public Google Drive download {args.label}: {args.expected_bytes} bytes", flush=True)
            started = time.monotonic()
            done = gdown.download(
                id=args.id, output=str(path), quiet=True, fuzzy=True, resume=True
            )
            if not done or not path.is_file():
                raise RuntimeError("Google Drive public download did not return ZIP bytes")
            size = path.stat().st_size
            print(f"Download complete {args.label}: {size} bytes in {round(time.monotonic() - started)}s", flush=True)
            if size != args.expected_bytes:
                raise ValueError(f"partial or unexpected bytes: {size} != {args.expected_bytes}")
            result = inspect_zip(path, archive_label=args.label, drive_file_id=args.id)
    except Exception as exc:
        result.update({"status": "failed", "error_type": type(exc).__name__, "error": str(exc)[:500]})
        print(f"Archive {args.label} failed: {type(exc).__name__}: {str(exc)[:500]}", flush=True)

    report.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    compact = {
        key: result[key] for key in (
            "archive", "status", "error_type", "error", "zip_bytes",
            "entry_count", "file_count", "extensions", "dataset_hints",
            "file_list_truncated"
        ) if key in result
    }
    compact["files_preview"] = result.get("file_list", [])[:30]
    compact["sample_headers"] = result.get("csv_header_samples", [])[:8]
    print("NETWORKPULSE_ARCHIVE_AUDIT_SUMMARY_START", flush=True)
    print(json.dumps(compact, ensure_ascii=False, separators=(",", ":")), flush=True)
    print("NETWORKPULSE_ARCHIVE_AUDIT_SUMMARY_END", flush=True)
    return int(result["status"] != "inspected")


if __name__ == "__main__":
    sys.exit(main())
