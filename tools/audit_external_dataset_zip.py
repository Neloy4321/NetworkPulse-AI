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



def _csv_columns_from_dictionary(zf: zipfile.ZipFile) -> list[str]:
    """UNSW raw partitions use headerless rows; dictionary supplies 49 names."""
    try:
        with zf.open("NUSW-NB15_features.csv") as source:
            content = source.read(16000).decode("utf-8-sig", errors="replace")
        return [row["Name"].strip() for row in csv.DictReader(io.StringIO(content))
                if row.get("Name")]
    except (KeyError, UnicodeError, csv.Error):
        return []


def _quick_member_profile(zf: zipfile.ZipFile, item: zipfile.ZipInfo,
                          columns: list[str], *, has_header: bool) -> dict:
    """Count physical CSV lines and sample five byte windows without extracting.

    Sampled label proportions are *not* population proportions. Compressed rows
    with embedded line breaks can make physical-line counts differ from CSV rows.
    """
    from datetime import datetime, timezone

    samples = 0
    invalid = 0
    label_values = Counter()
    type_values = Counter()
    time_bounds = []
    lower = [v.lower().strip() for v in columns]
    label_i = lower.index("label") if "label" in lower else None
    type_i = next((lower.index(n) for n in ("type", "attack_cat")
                   if n in lower), None)
    time_i = next((lower.index(n) for n in ("ts", "stime", "timestamp")
                   if n in lower), None)

    for fraction in (0, 0.2, 0.5, 0.8, 0.97):
        with zf.open(item) as stream:
            if fraction:
                stream.seek(int(max(0, item.file_size - 65536) * fraction))
                stream.readline(1000000)  # Discard a possibly partial line.
            elif has_header:
                stream.readline(1000000)  # Header only in one logical CSV.
            for _ in range(96):
                line = stream.readline(1000000)
                if not line:
                    break
                if not line.strip():
                    continue
                try:
                    row = next(csv.reader(io.StringIO(line.decode("utf-8-sig", errors="replace"))))
                except (csv.Error, StopIteration):
                    invalid += 1
                    continue
                if len(row) != len(columns):
                    invalid += 1
                    continue
                samples += 1
                if label_i is not None:
                    label_values[row[label_i].strip() or "[blank]"] += 1
                if type_i is not None:
                    type_values[row[type_i].strip() or "[blank]"] += 1
                if time_i is not None:
                    try:
                        stamp = float(row[time_i])
                        if 1_000_000_000 < stamp < 3_000_000_000:
                            time_bounds.append(stamp)
                    except (TypeError, ValueError, OverflowError):
                        pass
    physical_lines = 0
    with zf.open(item) as stream:
        while True:
            chunk = stream.read(8 * 1024 * 1024)
            if not chunk:
                break
            physical_lines += chunk.count(b"\\n")
    return {
        "file": item.filename,
        "physical_lines": physical_lines,
        "approx_records_if_no_embedded_newlines": max(0, physical_lines - int(has_header)),
        "header_present": has_header,
        "expected_columns": len(columns),
        "stratified_byte_window_sample_count": samples,
        "sampled_bad_column_count": invalid,
        "sampled_labels": dict(label_values.most_common(16)),
        "sampled_attack_types": dict(type_values.most_common(25)),
        "sampled_timestamp_min_utc": datetime.fromtimestamp(
            min(time_bounds), tz=timezone.utc).isoformat() if time_bounds else None,
        "sampled_timestamp_max_utc": datetime.fromtimestamp(
            max(time_bounds), tz=timezone.utc).isoformat() if time_bounds else None,
    }


def profile_archive(zf: zipfile.ZipFile, files: list[zipfile.ZipInfo]) -> dict:
    dictionary_columns = _csv_columns_from_dictionary(zf)
    profiles = []
    errors = []
    for item in files:
        if not item.filename.lower().endswith(".csv") or item.filename.endswith("_features.csv"):
            continue
        try:
            with zf.open(item) as stream:
                first = stream.readline(1000000).decode("utf-8-sig", errors="replace")
            header = next(csv.reader(io.StringIO(first)), [])
            # Zeek-like archive has named headers. Raw UNSW uses 49 dictionary names.
            has_header = "ts" in header[:3] and "src_ip" in header[:6]
            columns = header if has_header else dictionary_columns
            if not columns:
                errors.append({"file": item.filename, "error": "no matching header/dictionary"})
                continue
            profiles.append(_quick_member_profile(
                zf, item, columns, has_header=has_header
            ))
        except Exception as exc:
            errors.append({"file": item.filename,
                           "error": type(exc).__name__ + ": " + str(exc)[:130]})
    labels = Counter()
    types = Counter()
    for row in profiles:
        labels.update(row["sampled_labels"])
        types.update(row["sampled_attack_types"])
    return {
        "dictionary_column_count": len(dictionary_columns),
        "dictionary_column_names": dictionary_columns,
        "files_profiled": len(profiles),
        "physical_lines_total": sum(v["physical_lines"] for v in profiles),
        "sampled_rows_total": sum(v["stratified_byte_window_sample_count"]
                                  for v in profiles),
        "sampled_label_counts_not_prevalence": dict(labels.most_common(30)),
        "sampled_attack_type_counts_not_prevalence": dict(types.most_common(35)),
        "member_profiles": profiles,
        "profiling_errors": errors,
        "sample_method": "5 deterministic byte windows per file, up to 96 lines each; "
                         "counts are samples, not exact label prevalences",
    }


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
        result["row_profile"] = profile_archive(zf, files)
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
    profile = result.get("row_profile", {})
    compact["row_profile_summary"] = {key: profile.get(key) for key in (
        "files_profiled", "physical_lines_total", "dictionary_column_count",
        "sampled_rows_total", "sampled_label_counts_not_prevalence",
        "sampled_attack_type_counts_not_prevalence", "profiling_errors"
    ) if key in profile}
    compact["per_file_profiles_preview"] = profile.get("member_profiles", [])[:24]
    print("NETWORKPULSE_ARCHIVE_AUDIT_SUMMARY_START", flush=True)
    print(json.dumps(compact, ensure_ascii=False, separators=(",", ":")), flush=True)
    print("NETWORKPULSE_ARCHIVE_AUDIT_SUMMARY_END", flush=True)
    return int(result["status"] != "inspected")


if __name__ == "__main__":
    sys.exit(main())
