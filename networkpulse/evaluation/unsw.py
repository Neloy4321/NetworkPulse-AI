"""Reproducible external UNSW-NB15 CSV benchmark, not live-telemetry inference.

The official UNSW prepared partitions lack the flow identity and timestamps
required by the NetworkPulse canonical Zeek contract. Never invent missing
IP addresses, timestamps, or ports to force these rows through the API.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import random
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.neighbors import LocalOutlierFactor
from sklearn.feature_extraction import DictVectorizer
from sklearn.preprocessing import RobustScaler

FEATURE_NAMES = ("dur", "sbytes", "dbytes", "spkts", "dpkts", "rate", "sload", "dload")
REQUIRED = set(FEATURE_NAMES) | {"proto", "state", "label"}
DATASET = "UNSW-NB15-prepared-partitions"


def _finite(value: str, name: str) -> float:
    try:
        num = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid numeric {name}: {value!r}") from exc
    if not math.isfinite(num) or num < 0:
        raise ValueError(f"invalid numeric {name}: {value!r}")
    return min(num, 1e15)


def row_features(row: dict[str, str]) -> dict[str, float]:
    out = {"log_" + name: math.log1p(_finite(row[name], name)) for name in FEATURE_NAMES}
    total = _finite(row["sbytes"], "sbytes") + _finite(row["dbytes"], "dbytes")
    out["response_fraction"] = _finite(row["dbytes"], "dbytes") / max(1., total)
    out["proto=" + row["proto"].lower().strip()] = 1.
    out["state=" + row["state"].lower().strip()] = 1.
    return out


def fingerprint(row: dict[str, str]) -> str:
    # Raw benchmarking fields, never synthetic timestamps or unreliable IDs.
    keys = sorted(set(FEATURE_NAMES) | {"proto", "state", "service", "sttl", "dttl"})
    values = [str(row.get(k, "")).strip().lower() for k in keys]
    return hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()


def load_partition(path: Path, *, max_rows: int = 0, seed: int = 42) -> tuple[list[dict], dict]:
    """Seeded bounded reservoir sample; never silently take the first N rows."""
    rng = random.Random(seed)
    sample: list[dict] = []
    scanned = 0
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        missing = REQUIRED - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"{path}: missing UNSW columns: {sorted(missing)}")
        for row in reader:
            label = row["label"].strip()
            if label not in {"0", "1"}:
                raise ValueError(f"{path}: label must be 0 or 1")
            # validate and canonicalize up-front to fail on corrupt data
            record = {"x": row_features(row), "label": int(label), "attack_cat": row.get("attack_cat", "").strip(), "fingerprint": fingerprint(row)}
            scanned += 1
            if max_rows <= 0 or len(sample) < max_rows:
                sample.append(record)
            else:
                j = rng.randrange(scanned)
                if j < max_rows:
                    sample[j] = record
    if not sample:
        raise ValueError(f"{path}: empty dataset")
    return sample, {"path": str(path), "sha256": _hash_file(path), "rows_scanned": scanned, "rows_sampled": len(sample), "method": "full" if max_rows <= 0 else "seeded_reservoir"}


def _hash_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _unique(records: list[dict], blocked: set[str] | None = None) -> tuple[list[dict], int]:
    seen = set(blocked or ())
    clean = []
    for row in records:
        if row["fingerprint"] not in seen:
            clean.append(row)
            seen.add(row["fingerprint"])
    return clean, len(records) - len(clean)


def metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    pred = (scores >= threshold).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    return {
        "precision": round(float(precision), 5), "recall": round(float(recall), 5),
        "f1": round(float(f1), 5), "false_positive_rate": round(float(fp / max(1, (fp + tn))), 5),
        "threshold": round(float(threshold), 7),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "pr_auc": round(float(average_precision_score(y_true, scores)), 5) if len(set(y_true)) > 1 else None,
        "roc_auc": round(float(roc_auc_score(y_true, scores)), 5) if len(set(y_true)) > 1 else None,
        "alerts": int(pred.sum()),
    }


def evaluate_unsw(train_csv: Path, test_csv: Path, *, max_train: int = 15000,
                  max_test: int = 12000, seed: int = 42, quantile: float = .97) -> dict:
    if not .85 <= quantile <= .999:
        raise ValueError("calibration quantile must be between 0.85 and 0.999")
    if max_train and max_train < 200:
        raise ValueError("max_train must be >=200 or zero for all rows")
    tr, train_info = load_partition(train_csv, max_rows=max_train, seed=seed)
    te, test_info = load_partition(test_csv, max_rows=max_test, seed=seed+1)
    tr, train_duplicates = _unique(tr)
    te, test_duplicates = _unique(te, {x["fingerprint"] for x in tr})
    if not te:
        raise ValueError("no independent evaluation rows after leakage/duplicate filtering")
    # Unsupervised detectors are fit only on benign records; hold out a separate
    # random benign calibration set (the official prepared CSV is NOT time-ordered).
    normal = [x for x in tr if x["label"] == 0]
    rng = random.Random(seed)
    rng.shuffle(normal)
    split = int(len(normal)*.8)
    fitting, calibration = normal[:split], normal[split:]
    if len(fitting) < 80 or len(calibration) < 20:
        raise ValueError("not enough benign train and calibration rows")
    vec = DictVectorizer(sparse=False)
    a = vec.fit_transform([x["x"] for x in fitting])
    b = vec.transform([x["x"] for x in calibration])
    c = vec.transform([x["x"] for x in te])
    # Different distance scales matter for LOF; robust scaling shared with IF.
    scaler = RobustScaler().fit(a)
    a, b, c = scaler.transform(a), scaler.transform(b), scaler.transform(c)
    models = {
        "isolation_forest": IsolationForest(n_estimators=140, random_state=seed, n_jobs=1),
        "lof_novelty": LocalOutlierFactor(n_neighbors=min(25, len(fitting)-1), novelty=True, n_jobs=1),
    }
    y = np.array([x["label"] for x in te], dtype=int)
    results = {}
    for name, model in models.items():
        model.fit(a)
        cal_scores = -model.decision_function(b)
        scores = -model.decision_function(c)
        threshold = float(np.quantile(cal_scores, quantile))
        results[name] = metrics(y, scores, threshold)
    # Deterministic rule benchmark, not learned from test labels.
    # The feature contract does not contain destination-port or TCP state codes;
    # simple unusual high outbound volume + weak response is used instead.
    def rule_score(row: dict) -> float:
        x = row["x"]
        return float(x["log_sbytes"] > math.log1p(8000)) + float(x["response_fraction"] < .03) + float(x["log_dur"] < math.log1p(.07))
    rules_cal = np.array([rule_score(x) for x in calibration], dtype=float)
    # Keep target benign FPR comparable; strict > quantile handles ties.
    r_th = float(np.quantile(rules_cal, quantile)) + 1e-6
    results["rule_based"] = metrics(y, np.array([rule_score(x) for x in te]), r_th)
    attacks = Counter(x["attack_cat"] for x in te if x["label"] == 1)
    for name, result in results.items():
        # Attack-category recall is descriptive, not a universal unseen-attack test.
        if name == "rule_based":
            raw_score = [rule_score(x) for x in te]
            cut = r_th
        else:
            m = models[name]
            raw_score = -m.decision_function(c)
            cut = float(result["threshold"])
        pred = np.asarray(raw_score) >= cut
        result["attack_category_recall"] = {
            category: round(sum(bool(pred[i]) for i,x in enumerate(te)
                                if x["label"] == 1 and x["attack_cat"] == category)/count, 5)
            for category,count in attacks.items() if count > 0
        }
    return {
        "benchmark": DATASET,
        "dataset_provenance": {"source": "https://research.unsw.edu.au/projects/unsw-nb15-dataset", "train": train_info, "test": test_info},
        "split_policy": "published_train_test_partition + seeded_benign_only_train_calibration",
        "temporal_split_verified": False, "cross_site_shift_verified": False,
        "note": "Official prepared partitions have no reliable chronological field. Training is fit on benign rows; labels only evaluate the independent official test partition. This is a cyber-range benchmark, not production traffic.",
        "dropped_duplicates": {"train": train_duplicates, "test_within_and_cross_split": test_duplicates},
        "sample_counts": {"fitting_benign": len(fitting), "calibration_benign": len(calibration), "test": len(te), "test_attacks": int(y.sum())},
        "test_attack_categories": dict(attacks),
        "features": list(vec.feature_names_), "evaluation": results,
        "limitations": ["Official prepared partitions lack reliable source IP, destination port and event timestamp; these are not fabricated.","Random benign calibration inside published training partition is not chronological.","Feature-space benchmark models are separate from the Zeek/Suricata live detector.","Unequal or capped reservoir sampling can alter class prevalence; interpret precision and FPR accordingly."]
    }


def write_report(result: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
