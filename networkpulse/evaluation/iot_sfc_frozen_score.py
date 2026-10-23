"""Real frozen V2 RF source-transfer diagnostic, never operational acceptance.

Frozen SHA-256 and 0.20 threshold cannot be tuned from target labels.
Only aggregate metrics from the first-N positional IoT-SFC v7 CSV rows.
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
from collections import Counter, defaultdict
from itertools import islice
from pathlib import Path

import joblib
import numpy as np
import sklearn

from networkpulse.evaluation.iot_sfc_preregistration import (
    MODEL_SHA, MODEL_PROTOCOL_SHA, TARGET_SHA, TARGET_SIZE,
)
from networkpulse.evaluation.iot_sfc_v7_conn_adapter import (
    RowNotEligible, conn_log_to_flow_v2, inspect_untrusted_producer_label,
    verify_exact_header,
)
from networkpulse.evaluation.v2_calibrated_new_lab_eval import bin_metrics
from networkpulse.feature_contract_v2 import features_v2

CUTOFF = 0.20
MEMBER = "iot_dataset_v7.csv"
UNCOMPRESSED = 13_561_863_941
MAX_ROWS = 400_000
BATCH = 2048


def digest(path: Path) -> str:
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("Nonregular or symlink input refused")
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_bytes(zipped: Path, model: Path, manifest_path: Path) -> None:
    if zipped.name != "iot_dataset_v7.zip" or zipped.stat().st_size != TARGET_SIZE:
        raise ValueError("Target archive identity changed")
    if digest(zipped) != TARGET_SHA or digest(model) != MODEL_SHA:
        raise ValueError("Frozen source model or ZIP SHA mismatch")
    if manifest_path.stat().st_size > 100_000 or manifest_path.is_symlink():
        raise ValueError("Invalid manifest bytes")
    m = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (m.get("artifact_sha256") != MODEL_SHA
            or m.get("protocol_sha256") != MODEL_PROTOCOL_SHA
            or m.get("protocol", {}).get("threshold") != CUTOFF
            or m.get("protocol", {}).get("feature_contract") != "missingness_aware_flow_v2"
            or m.get("production_signed") is not False):
        raise ValueError("Frozen research model/threshold/manifest changed")


def adapt_v7_conn(row: dict[str, str]):
    """Source-specific, observed literal conn -> existing conn.log adapter."""
    if row.get("log_type") != "conn":
        raise RowNotEligible("not_v7_native_conn_stem")
    canonical = dict(row)
    canonical["log_type"] = "conn.log"
    return conn_log_to_flow_v2(canonical)


def _batch(bundle: dict, flows: list, labels: list, days: list,
           combined: Counter, day_counts: dict):
    if not flows:
        return
    vector = bundle["vectorizer"].transform([features_v2(f) for f in flows])
    probabilities = bundle["estimator"].predict_proba(vector)
    if probabilities.shape != (len(flows), 2) or not np.isfinite(probabilities).all():
        raise ValueError("Bad frozen classifier probabilities")
    for positive, label, day in zip(probabilities[:, 1] >= CUTOFF, labels, days):
        cell = ("tp" if label else "fp") if positive else ("fn" if label else "tn")
        combined[cell] += 1
        day_counts[day][cell] += 1


def _quality(counts: Counter) -> dict:
    tn, fp, fn, tp = (counts[k] for k in ("tn", "fp", "fn", "tp"))
    n0, n1 = tn + fp, fn + tp
    if n0 and n1:
        y = np.r_[np.zeros(n0, dtype=int), np.ones(n1, dtype=int)]
        pred = np.r_[np.zeros(tn, dtype=bool), np.ones(fp, dtype=bool),
                     np.zeros(fn, dtype=bool), np.ones(tp, dtype=bool)]
        m = bin_metrics(y, pred)
        m.pop("numeric_research_pass", None)
    else:
        m = {"status": "BLOCKED_CLASS_SUPPORT",
             "confusion": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
             "benign": n0, "attack": n1,
             "fpr_upper_95": None, "recall_lower_95": None}
    m["ground_truth_independently_adjudicated"] = False
    m["true_acceptance"] = "NOT_ESTABLISHED"
    return m


def score_prefix(archive: Path, model: Path, manifest: Path,
                 *, max_rows: int = 200_000) -> dict:
    if type(max_rows) is not int or not 1 <= max_rows <= MAX_ROWS:
        raise ValueError("Unbounded or invalid row limit")
    verify_bytes(archive, model, manifest)
    if sklearn.__version__ != "1.9.1":
        raise ValueError("Exact sklearn 1.9.1 runtime required")
    # This is a repository-generated GitHub Actions artifact with a pinned SHA;
    # never deserialize a model supplied from elsewhere.
    bundle = joblib.load(model)
    if (bundle.get("scikit_learn_version") != sklearn.__version__
            or bundle.get("fixed_cutoff") != CUTOFF
            or bundle.get("feature_contract") != "missingness_aware_flow_v2"
            or bundle.get("protocol_sha256") != MODEL_PROTOCOL_SHA
            or bundle.get("production_approved") is not False):
        raise ValueError("Model bundle contract differs from frozen baseline")
    rows_seen = 0
    statuses = Counter()
    total = Counter()
    days = defaultdict(Counter)
    in_batch, label_batch, day_batch = [], [], []
    seen_identities = set()
    with zipfile.ZipFile(archive, "r", allowZip64=True) as zf:
        entries = zf.infolist()
        if len(entries) != 1 or entries[0].filename != MEMBER:
            raise ValueError("Unexpected ZIP member")
        member = entries[0]
        if (member.file_size != UNCOMPRESSED or member.flag_bits & 1
                or member.is_dir() or member.compress_type != zipfile.ZIP_DEFLATED):
            raise ValueError("Unexpected member size/type/encryption")
        with zf.open(member) as raw:
            with io.TextIOWrapper(raw, encoding="utf-8-sig", newline="") as source:
                previous = csv.field_size_limit()
                csv.field_size_limit(131072)
                try:
                    reader = csv.reader(source, strict=True)
                    header = next(reader)
                    verify_exact_header(header)
                    for cells in islice(reader, max_rows):
                        rows_seen += 1
                        if len(cells) != len(header):
                            statuses["bad_row_width"] += 1
                            continue
                        row = dict(zip(header, cells))
                        if row.get("log_type") != "conn":
                            statuses["non_conn_excluded"] += 1
                            continue
                        statuses["conn_seen"] += 1
                        try:
                            flow = adapt_v7_conn(row)
                        except RowNotEligible:
                            statuses["invalid_conn"] += 1
                            continue
                        try:
                            producer = inspect_untrusted_producer_label(row)
                        except RowNotEligible:
                            statuses["invalid_or_missing_producer_label"] += 1
                            continue
                        fingerprint = (
                            flow.uid, flow.timestamp, str(flow.src_ip), str(flow.dst_ip),
                            flow.src_port, flow.dst_port, flow.proto
                        )
                        if fingerprint in seen_identities:
                            statuses["duplicate_flow"] += 1
                            continue
                        seen_identities.add(fingerprint)
                        statuses["scored_unreviewed_producer_label"] += 1
                        in_batch.append(flow)
                        label_batch.append(producer.producer_class)
                        day_batch.append(flow.timestamp.date().isoformat())
                        if len(in_batch) >= BATCH:
                            _batch(bundle, in_batch, label_batch, day_batch, total, days)
                            in_batch, label_batch, day_batch = [], [], []
                    _batch(bundle, in_batch, label_batch, day_batch, total, days)
                finally:
                    csv.field_size_limit(previous)
    if (sum(total.values()) != statuses["scored_unreviewed_producer_label"]
            or rows_seen != sum(statuses[k] for k in (
                "bad_row_width", "non_conn_excluded", "invalid_conn",
                "invalid_or_missing_producer_label", "duplicate_flow",
                "scored_unreviewed_producer_label"
            ))):
        raise ValueError("Confusion and source row reconciliation failed")
    return {
        "status": "FROZEN_RESEARCH_TRANSFER_NUMERICAL_OBSERVATION_NOT_ACCEPTANCE",
        "original_dataset_sha256": TARGET_SHA,
        "frozen_model_sha256": MODEL_SHA,
        "threshold": CUTOFF,
        "sample_source": "FIRST_N_CSV_ROWS_NONREPRESENTATIVE",
        "rows_seen": rows_seen,
        "eligibility": dict(statuses),
        "descriptive_metrics": _quality(total),
        "per_day": {d: _quality(v) for d, v in sorted(days.items())},
        "distinct_eligible_capture_days": len(days),
        "trained_or_tuned_on_target": False,
        "source_labels_independently_verified": False,
        "cross_source_leakage_excluded": False,
        "original_archive_full_crc_verified": False,
        "original_raw_records_persisted": False,
        "research_quality_acceptance": "NOT_ESTABLISHED",
        "independent_operational_site": False,
        "signed_active_deployment": False,
        "p0_operational_ml_acceptance": "NO_GO",
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", required=True, type=Path)
    p.add_argument("--model", required=True, type=Path)
    p.add_argument("--manifest", required=True, type=Path)
    p.add_argument("--max-rows", type=int, default=200000)
    p.add_argument("--report", required=True, type=Path)
    args = p.parse_args()
    if args.report.exists() or args.report.is_symlink():
        p.error("Refuse overwriting numerical evidence")
    report = score_prefix(args.archive, args.model, args.manifest, max_rows=args.max_rows)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.report, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(report, out, sort_keys=True, indent=2, allow_nan=False)
        out.write("\n")
    print(json.dumps({"metrics": report["descriptive_metrics"],
                      "p0_operational_ml_acceptance": "NO_GO"}, sort_keys=True))


if __name__ == "__main__":
    main()
