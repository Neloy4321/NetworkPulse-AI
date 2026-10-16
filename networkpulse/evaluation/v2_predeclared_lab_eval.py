"""Fixed V2 RF laboratory-capture transfer study: 8-1 Hakai & 20-1 Torii.

PREREGISTERED source URLs and cutoff were committed before scoring either
scenario. IoT-23v2 is one laboratory dataset FAMILY, not independent field
acceptance. No release, retraining on scored target, target threshold search
or model choice is permitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path

import joblib
import numpy as np

from networkpulse.evaluation.iot23v2_source_adapter import COLUMNS, _require_header
from networkpulse.evaluation.unsw_to_toniot import digest
from networkpulse.evaluation.v2_mixed_source_freeze import (
    FIXED_CUTOFF, PROTOCOL, protocol_digest,
)
from networkpulse.feature_contract_v2 import (
    V2_FEATURE_CONTRACT, features_v2, from_zeek_v2,
)
from networkpulse.generalization_evidence import wilson_interval

FROZEN_SOURCE_V2_SHA = (
    "a1b90b4f26b98cfa00b65fd218d90ef5af97e800cf636ecfe8fa5620be6c4589"
)
CAPTURES = {
    "CTU-IoT-Malware-Capture-8-1": (
        "2018-07-31-15-15-09-192.168.100.113-zeek-conn-log.labeled"
    ),
    "CTU-IoT-Malware-Capture-20-1": (
        "2018-10-02-13-12-30-192.168.100.103-zeek-conn-log.labeled"
    ),
}
REGISTERED = tuple(CAPTURES)
MAX_SOURCE_BYTES = 10_000_000
MAX_ROWS = 150000
MIN_BENIGN = 200
MIN_ATTACK = 100


def parse_capture(path: Path):
    if path.stat().st_size > MAX_SOURCE_BYTES or not path.stat().st_size:
        raise ValueError("unregistered or empty source byte budget")
    rows = []
    labels = []
    counted = Counter()
    seen = set()
    has_header = False
    for line_no, raw in enumerate(path.open("r", encoding="utf-8"), 1):
        if raw.startswith("#fields\t"):
            _require_header(raw)
            has_header = True
            continue
        if raw.startswith("#"):
            continue
        if not has_header or len(rows) >= MAX_ROWS:
            raise ValueError("missing Zeek header or source row limit exceeded")
        parts = raw.rstrip("\r\n").split("\t")
        if len(parts) != 21:
            raise ValueError("unregistered Zeek schema width")
        trailer = re.split(r"\s{2,}", parts[20].strip())
        if len(trailer) != 3 or trailer[1] not in ("Benign", "Malicious"):
            raise ValueError("unknown/ambiguous source label")
        event = from_zeek_v2(dict(zip(COLUMNS, parts[:20])))
        # CID must be unique; labels must not enter features or training.
        key = (str(event.src_ip), str(event.dst_ip), event.uid, event.timestamp,
               event.src_port, event.dst_port, event.proto)
        if key in seen:
            raise ValueError("duplicate source flow; do not inflate effective test size")
        seen.add(key)
        features = features_v2(event)
        if any(not math.isfinite(val) for val in features.values()):
            raise ValueError("nonfinite V2 model inputs")
        rows.append(event)
        labels.append(int(trailer[1] == "Malicious"))
        counted["malicious" if labels[-1] else "benign"] += 1
        if any(getattr(event, name) is None for name in (
            "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"
        )):
            counted["missing_numeric"] += 1
    if not has_header or not rows:
        raise ValueError("source does not contain labeled Zeek flows")
    return rows, np.asarray(labels, dtype=int), counted


def score(model, captured_rows, labels, counters):
    if model.get("feature_contract") != V2_FEATURE_CONTRACT:
        raise ValueError("model is not the already registered V2 feature contract")
    if (model.get("schema_version") != 2 or model.get("production_approved") is not False
            or model.get("protocol_sha256") != protocol_digest()
            or model.get("fixed_cutoff") != FIXED_CUTOFF):
        raise ValueError("original frozen V2 source/model protocol mismatch")
    if not all(getattr(e, "label") is None for e in captured_rows):
        raise ValueError("target label accidentally embedded in inference input")
    result = {
        "source_rows": len(captured_rows),
        "benign_rows": counters["benign"],
        "attack_rows": counters["malicious"],
        "missing_numeric_rows": counters["missing_numeric"],
        "status": "blocked_insufficient_natural_class_support",
        "quality_numeric_research_only": None,
        "metrics": None,
    }
    if counters["benign"] < MIN_BENIGN or counters["malicious"] < MIN_ATTACK:
        return result
    x = model["vectorizer"].transform([features_v2(e) for e in captured_rows])
    probabilities = model["estimator"].predict_proba(x)
    if probabilities.shape != (len(captured_rows), 2):
        raise ValueError("incompatible frozen research classifier outputs")
    scores = probabilities[:, 1]
    if not np.isfinite(scores).all() or (scores < 0).any() or (scores > 1).any():
        raise ValueError("out-of-bound research model outputs")
    positive = scores >= FIXED_CUTOFF
    tp = int(np.sum(positive & (labels == 1)))
    fp = int(np.sum(positive & (labels == 0)))
    tn = int(np.sum(~positive & (labels == 0)))
    fn = int(np.sum(~positive & (labels == 1)))
    fpr = fp / (fp + tn)
    recall = tp / (tp + fn)
    fpr_ci = wilson_interval(fp, fp + tn)
    recall_ci = wilson_interval(tp, tp + fn)
    result.update({
        "status": "measured_exposed_iot23v2_lab_capture_not_operational_acceptance",
        "metrics": {
            "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
            "fpr": round(fpr, 6), "recall": round(recall, 6),
            "fpr_wilson95": list(fpr_ci),
            "recall_wilson95": list(recall_ci),
        },
        "quality_numeric_research_only": (
            fpr_ci[1] <= 0.05 and recall_ci[0] >= 0.80
        ),
    })
    return result


def evaluate(bundle: Path, manifest_path: Path, sources: dict[str, Path]) -> dict:
    if tuple(sources) != REGISTERED:
        raise ValueError("only the two pre-registered research targets are allowed")
    if digest(bundle) != FROZEN_SOURCE_V2_SHA:
        raise ValueError("unapproved V2 frozen model bytes")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (manifest.get("artifact_sha256") != FROZEN_SOURCE_V2_SHA or
            manifest.get("protocol") != PROTOCOL or
            manifest.get("production_signed") is not False or
            manifest.get("independent_test_performed") is not False):
        raise ValueError("unapproved model manifest or incorrect production claim")
    # Trusted locally recreated bundle pinned by source-side SHA before pickle.
    frozen = joblib.load(bundle)
    if frozen.get("scikit_learn_version") != __import__("sklearn").__version__:
        raise ValueError("runtime version differs from the frozen source model")
    captures = []
    for capture, path in sources.items():
        if path.name != CAPTURES[capture]:
            raise ValueError("unexpected file identity in pre-registered target")
        target_sha = digest(path)  # SHA is recorded BEFORE flow parsing/scoring.
        records, labels, support = parse_capture(path)
        results = score(frozen, records, labels, support)
        captures.append({
            "capture": capture,
            "original_source_sha256": target_sha,
            **results,
        })
    if digest(bundle) != FROZEN_SOURCE_V2_SHA:
        raise ValueError("research model changed while scoring")
    return {
        "schema_version": 1,
        "status": "two_predeclared_lab_capture_v2_research_test_completed",
        "research_only": True,
        "frozen_model_sha256": FROZEN_SOURCE_V2_SHA,
        "feature_contract": V2_FEATURE_CONTRACT,
        "fixed_probability_cutoff": FIXED_CUTOFF,
        "training_source_iot34_exposed": True,
        "training_or_threshold_adjusted_after_new_target": False,
        "independent_operator_site_validated": False,
        "production_model_signed_and_active": False,
        "p0_operational_ml_acceptance": "NO_GO",
        "capture_results": captures,
        "limitations": [
            "Training included IoT-23 capture 34-1 from the same research lab family.",
            "Target 8-1 and 20-1 captures come from a shared Stratosphere lab.",
            "No independent deployed SOC or analyst labels verified.",
            "Sensor semantics and in-field alert-hour burden not established.",
            "Wilson flow intervals ignore within-host/session correlation.",
            "Signed active production Detector remains original IsolationForest.",
            "Do not re-optimize model against outcomes of these now-exposed captures.",
        ],
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--frozen-bundle", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--capture-8", type=Path, required=True)
    p.add_argument("--capture-20", type=Path, required=True)
    p.add_argument("--aggregate-output", type=Path, required=True)
    args = p.parse_args()
    if args.aggregate_output.exists():
        p.error("refuse overwrite predeclared research evidence")
    result = evaluate(
        args.frozen_bundle, args.manifest,
        {
            REGISTERED[0]: args.capture_8,
            REGISTERED[1]: args.capture_20,
        },
    )
    args.aggregate_output.parent.mkdir(parents=True, exist_ok=True)
    with args.aggregate_output.open("x", encoding="utf-8") as out:
        json.dump(result, out, indent=2, sort_keys=True, allow_nan=False)
        out.write("\n")
    print(json.dumps({
        "status": result["status"],
        "research_capture_results": [
            {"capture": c["capture"], "status": c["status"],
             "count": c["source_rows"], "metrics": c["metrics"]}
            for c in result["capture_results"]
        ],
        "p0_operational_ml_acceptance": "NO_GO",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
