"""Real external network-IDS benchmarks from source ZIPs; no raw rows exported.

Separate capture files/days are used for fit vs test, with benign-only
calibration for unsupervised novelty and training-only labels for RF reference.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import random
import zipfile
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import RobustScaler

SPECS = {
    "toniot": ("Network_dataset_1.csv", "Network_dataset_23.csv"),
    "unsw_raw": ("UNSW-NB15_1.csv", "UNSW-NB15_4.csv"),
    "cic2017": (
        "MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv",
        "MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    ),
}
UNSW_COLUMNS = (
    "srcip sport dstip dsport proto state dur sbytes dbytes sttl dttl sloss "
    "dloss service Sload Dload Spkts Dpkts swin dwin stcpb dtcpb smeansz "
    "dmeansz trans_depth res_bdy_len Sjit Djit Stime Ltime Sintpkt Dintpkt "
    "tcprtt synack ackdat is_sm_ips_ports ct_state_ttl ct_flw_http_mthd "
    "is_ftp_login ct_ftp_cmd ct_srv_src ct_srv_dst ct_dst_ltm ct_src_ltm "
    "ct_src_dport_ltm ct_dst_sport_ltm ct_dst_src_ltm attack_cat Label"
).split()


def _float(v: str, name: str) -> float:
    try:
        x = float(str(v).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid {name}") from exc
    if not math.isfinite(x) or x < 0 or x > 1e15:
        raise ValueError(f"invalid range {name}")
    return x


def parse_flow(row: dict[str, str], dataset: str) -> dict:
    """Only numeric flow metadata + protocol/state; no IP, UID, time or labels."""
    x = {str(k).strip().lower(): (v or "").strip() for k, v in row.items()}
    if dataset == "toniot":
        keys = ("duration", "src_bytes", "dst_bytes", "src_pkts", "dst_pkts", "dst_port")
        label, category, ts, proto, state = (
            x["label"], x["type"], _float(x["ts"], "ts"), x["proto"], x["conn_state"]
        )
        duration, sent, received, sp, dp, port = (_float(x[k], k) for k in keys)
    elif dataset == "unsw_raw":
        keys = ("dur", "sbytes", "dbytes", "spkts", "dpkts", "dsport")
        label, category, ts, proto, state = (
            x["label"], x["attack_cat"], _float(x["stime"], "stime"), x["proto"], x["state"]
        )
        duration, sent, received, sp, dp, port = (_float(x[k], k) for k in keys)
    elif dataset == "cic2017":
        keys = (
            "flow duration", "total length of fwd packets",
            "total length of bwd packets", "total fwd packets",
            "total backward packets", "destination port",
        )
        if not x["label"]:
            raise ValueError("empty CIC label")
        label, category, ts, proto, state = (
            "0" if x["label"].casefold() == "benign" else "1",
            x["label"], None, "unknown", "unknown",
        )
        duration, sent, received, sp, dp, port = (_float(x[k], k) for k in keys)
        duration /= 1e6  # CICFlowMeter microseconds; others use seconds.
    else:
        raise ValueError("unsupported dataset")
    if label not in {"0", "1"}:
        raise ValueError("invalid binary label")
    if not 0 <= port <= 65535 or not port.is_integer():
        raise ValueError("invalid destination port")
    features = {
        "log_duration_s": math.log1p(duration),
        "log_sent_bytes": math.log1p(sent),
        "log_recv_bytes": math.log1p(received),
        "log_sent_packets": math.log1p(sp),
        "log_recv_packets": math.log1p(dp),
        "log_byte_rate": math.log1p(min(1e12, (sent + received) / max(duration, 1e-4))),
        "recv_fraction": received / max(1., sent + received),
        "log_dst_port": math.log1p(port),
        "well_known_port": int(port < 1024),
        "proto=" + proto.lower(): 1.,
        "state=" + state.lower(): 1.,
    }
    signature = json.dumps(sorted(features.items()), separators=(",", ":"))
    return {
        "features": features, "label": int(label), "category": category,
        "timestamp": ts, "fingerprint": hashlib.sha256(signature.encode()).hexdigest(),
    }


def stream_sample(zf: zipfile.ZipFile, member: str, dataset: str,
                  limit: int, seed: int) -> tuple[list[dict], dict]:
    """One full streamed scan plus a seeded, unbiased bounded reservoir."""
    rng = random.Random(seed)
    records: list[dict] = []
    seen, rejected, counts = 0, 0, Counter()
    info = zf.getinfo(member)
    with zf.open(member) as f:
        stream = io.TextIOWrapper(f, encoding="utf-8-sig", errors="replace", newline="")
        reader = (csv.DictReader(stream, fieldnames=UNSW_COLUMNS)
                  if dataset == "unsw_raw" else csv.DictReader(stream))
        for row in reader:
            try:
                parsed = parse_flow(row, dataset)
            except (KeyError, ValueError, TypeError, AttributeError):
                rejected += 1
                continue
            seen += 1
            counts[str(parsed["label"])] += 1
            if len(records) < limit:
                records.append(parsed)
            else:
                pos = rng.randrange(seen)
                if pos < limit:
                    records[pos] = parsed
    return records, {
        "file_name": member, "file_size_uncompressed": info.file_size,
        "zip_member_crc32": format(info.CRC, "08x"),
        "valid_rows_full_scan": seen, "invalid_rows_full_scan": rejected,
        "label_counts_full_scan": dict(counts),
        "sampled_rows": len(records),
        "sampling": "uniform seeded reservoir across valid rows",
    }


def unique(records: list[dict], deny: set[str] | None = None):
    seen = set(deny or ())
    out = []
    for row in records:
        if row["fingerprint"] not in seen:
            seen.add(row["fingerprint"])
            out.append(row)
    return out, len(records) - len(out)


def _metric(y: np.ndarray, score: np.ndarray, threshold: float,
            categories: list[str]) -> dict:
    pred = np.asarray(score > threshold, dtype=int)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y, pred, average="binary", zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    cats = Counter(categories[i] for i, v in enumerate(y) if v == 1)
    return {
        "precision": round(float(precision), 5),
        "recall": round(float(recall), 5),
        "f1": round(float(f1), 5),
        "false_positive_rate": round(float(fp / max(1, fp + tn)), 5),
        "roc_auc": round(float(roc_auc_score(y, score)), 5) if len(np.unique(y)) == 2 else None,
        "pr_auc": round(float(average_precision_score(y, score)), 5) if len(np.unique(y)) == 2 else None,
        "confusion_matrix": dict(tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp)),
        "calibrated_threshold": round(float(threshold), 7),
        "alert_fraction": round(float(np.mean(pred)), 5),
        "per_attack_recall": {
            cat: round(sum(bool(pred[i]) for i, v in enumerate(y)
                           if v == 1 and categories[i] == cat) / n, 5)
            for cat, n in cats.items()
        },
    }


def evaluate(path: Path, dataset: str, *, seed: int = 42,
             max_train: int = 2200, max_test: int = 1300,
             quantile: float = .97) -> dict:
    if dataset not in SPECS or max_train < 500 or max_test < 300:
        raise ValueError("unsupported dataset or sample caps")
    if not .85 < quantile < 1.:
        raise ValueError("invalid quantile")
    with zipfile.ZipFile(path) as zf:
        train_name, test_name = SPECS[dataset]
        train, trmeta = stream_sample(zf, train_name, dataset, max_train, seed)
        test, temeta = stream_sample(zf, test_name, dataset, max_test, seed + 1)
    if dataset == "unsw_raw" and len(UNSW_COLUMNS) != 49:
        raise AssertionError("invalid official UNSW raw feature dictionary")
    train, dtrain = unique(train)
    test, dtest = unique(test, {r["fingerprint"] for r in train})
    if len(test) < 100:
        raise ValueError("test too small after cross-partition duplicate removal")
    chrono = dataset in {"toniot", "unsw_raw"}
    split = {
        "train_capture": train_name, "test_capture": test_name,
        "file_separated_holdout": True,
        "site_independence_verified": False,
        "training_and_test_capture_time_separated": False,
        "calibration_chronological": False,
    }
    if chrono:
        low_train = min(r["timestamp"] for r in train)
        high_train = max(r["timestamp"] for r in train)
        low_test = min(r["timestamp"] for r in test)
        high_test = max(r["timestamp"] for r in test)
        split.update(train_timestamp_min=low_train, train_timestamp_max=high_train,
                     test_timestamp_min=low_test, test_timestamp_max=high_test)
        if not high_train < low_test:
            raise ValueError("capture periods overlap; invalid temporal holdout")
        split["training_and_test_capture_time_separated"] = True

    benign = [r for r in train if r["label"] == 0]
    if len(benign) < 130:
        raise ValueError("insufficient benign-only training/calibration records")
    if chrono:
        benign.sort(key=lambda r: r["timestamp"])
    else:
        random.Random(seed).shuffle(benign)
    divider = int(.75 * len(benign))
    fit, calibration = benign[:divider], benign[divider:]
    if chrono:
        max_fit = fit[-1]["timestamp"]
        calibration = [r for r in calibration if r["timestamp"] > max_fit]
        if len(calibration) < 30:
            raise ValueError("no valid later-time benign calibration")
        split["calibration_chronological"] = True
        split["max_fit_timestamp"] = max_fit
        split["min_calibration_timestamp"] = calibration[0]["timestamp"]
    else:
        split["calibration_note"] = "Benign random calibration Wednesday; later Friday test"

    v = DictVectorizer(sparse=False)
    a = v.fit_transform([r["features"] for r in fit])
    b = v.transform([r["features"] for r in calibration])
    c = v.transform([r["features"] for r in test])
    scaler = RobustScaler().fit(a)
    a, b, c = scaler.transform(a), scaler.transform(b), scaler.transform(c)
    models = {
        "isolation_forest": IsolationForest(
            n_estimators=120, random_state=seed, n_jobs=1
        ),
        "lof_novelty": LocalOutlierFactor(
            n_neighbors=25, novelty=True, n_jobs=1
        ),
    }
    y = np.array([r["label"] for r in test], dtype=int)
    if set(y) != {0, 1}:
        raise ValueError("test must contain benign and attacks")
    categories = [r["category"] for r in test]
    results = {}
    for name, model in models.items():
        model.fit(a)
        cal_scores = -model.decision_function(b)
        scores = -model.decision_function(c)
        threshold = float(np.quantile(cal_scores, quantile))
        results[name] = _metric(y, scores, threshold, categories)

    # Supervised RF is a separate reference. It learns attacks from the EARLIER
    # training capture only, never from the independent test capture.
    if chrono:
        train.sort(key=lambda r: r["timestamp"])
    else:
        random.Random(seed).shuffle(train)
    boundary = int(.75 * len(train))
    rf_fit = train[:boundary]
    rf_cal = [r for r in train[boundary:] if r["label"] == 0]
    if len(rf_cal) >= 30 and len({r["label"] for r in rf_fit}) == 2:
        rf = RandomForestClassifier(
            n_estimators=120, min_samples_leaf=3, max_depth=14,
            class_weight="balanced_subsample", random_state=seed, n_jobs=1,
        )
        rf_a = scaler.transform(v.transform([r["features"] for r in rf_fit]))
        rf_b = scaler.transform(v.transform([r["features"] for r in rf_cal]))
        rf.fit(rf_a, np.asarray([r["label"] for r in rf_fit]))
        attack_idx = list(rf.classes_).index(1)
        benign_p = rf.predict_proba(rf_b)[:, attack_idx]
        test_p = rf.predict_proba(c)[:, attack_idx]
        results["supervised_random_forest"] = _metric(
            y, test_p, float(np.quantile(benign_p, quantile)), categories
        )
        split["supervised_fit_capture_train_count"] = len(rf_fit)
        split["supervised_calibration_benign_count"] = len(rf_cal)
        split["supervised_uses_training_capture_attack_labels"] = True
    else:
        split["supervised_reference_unavailable"] = "Not enough training classes/calibration"

    def rule(f):
        return (float(f["recv_fraction"] < .025)
                + float(f["log_byte_rate"] > math.log1p(500_000))
                + float(f["log_dst_port"] > math.log1p(49_151)))

    cutoff = float(np.quantile([rule(r["features"]) for r in calibration], quantile))
    results["fixed_rules"] = _metric(
        y, np.asarray([rule(r["features"]) for r in test]), cutoff, categories
    )
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for part in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(part)
    return {
        "benchmark": dataset, "dataset_is_real_external": True,
        "held_out_dataset_is_production_traffic": False,
        "archive_sha256": digest.hexdigest(),
        "archive_size_bytes": path.stat().st_size,
        "source_files": {"train": trmeta, "test": temeta},
        "sampling_seed": seed,
        "sample_caps": {"train": max_train, "test": max_test},
        "sampling_is_full_population": False,
        "split": split,
        "deduplication": {"train_within": dtrain, "test_within_and_cross": dtest},
        "sample_counts": {
            "benign_available": len(benign),
            "fit_benign": len(fit), "calibration_benign": len(calibration),
            "test": len(test), "test_benign": int((y == 0).sum()),
            "test_attacks": int(y.sum()),
        },
        "attack_categories_test": dict(Counter(
            r["category"] for r in test if r["label"] == 1
        )),
        "model_feature_schema": list(v.feature_names_),
        "model_results": results,
        "limitations": [
            "Train/test captures are disjoint files, not verified independent network sites.",
            "Reservoir sampled results reflect held-out files, not unknown deployment prevalence.",
            "Identifiers, addresses, raw timestamps, URI and attack labels excluded from features.",
            "Unsupervised models use only training benign and benign calibration records.",
            "Supervised reference uses training-day attack labels but not test-day labels.",
            "Offline baseline is NOT accuracy of deployed Zeek/Suricata model.",
            "Production false-alarm budgets and external independent-site testing remain.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zip", type=Path, required=True)
    parser.add_argument("--dataset", choices=SPECS, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-train", type=int, default=2200)
    parser.add_argument("--max-test", type=int, default=1300)
    args = parser.parse_args()
    result = evaluate(args.zip, args.dataset, seed=args.seed,
                      max_train=args.max_train, max_test=args.max_test)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({
        "dataset": result["benchmark"], "source_files": result["source_files"],
        "split": result["split"], "sample_counts": result["sample_counts"],
        "model_results": result["model_results"],
    }, indent=2))


if __name__ == "__main__":
    main()
