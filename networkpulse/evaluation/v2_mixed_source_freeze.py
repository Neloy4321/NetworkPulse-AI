"""Reproducible mixed-exposed-source V2 model training, NOT acceptance.

Both the UNSW family and this one IoT-23v2 capture were previously inspected
before model choice: they are *development/training*, not holdouts.
No external labels are consulted as held-out test labels. A NEW independent
authorized collection is required for actual ML acceptance after this freeze.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import zipfile
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer

from networkpulse.evaluation.iot23v2_exact_runtime_recheck import (
    SOURCE_BYTES as IOT_BYTES, SOURCE_SHA256 as IOT_SHA,
)
from networkpulse.evaluation.iot23v2_source_adapter import COLUMNS, _require_header
from networkpulse.evaluation.live_unsw import read_reservoir
from networkpulse.evaluation.source_only_feature_audit import SOURCE_EXPECTED_BYTES
from networkpulse.evaluation.source_only_loco import (
    MEMBERS, MEMBER_SEEDS, SAMPLE_PER_MEMBER,
)
from networkpulse.evaluation.unsw_to_toniot import UNSW_SHA, digest, unique
from networkpulse.feature_contract_v2 import (
    V2_FEATURE_CONTRACT, FlowV2, features_v2, from_zeek_v2,
)

SEED = 42
FIXED_CUTOFF = 0.5
ESTIMATOR = {
    "n_estimators": 160,
    "max_depth": 12,
    "min_samples_leaf": 10,
    "class_weight": "balanced_subsample",
    "random_state": SEED,
    "n_jobs": 1,
}
PROTOCOL = {
    "feature_contract": V2_FEATURE_CONTRACT,
    "source_families": ["UNSW-NB15", "IoT-23v2"],
    "source_shas": [UNSW_SHA, IOT_SHA],
    "unsw_csv_parts": list(MEMBERS),
    "unsw_per_part_sample": SAMPLE_PER_MEMBER,
    "unsw_seeds": list(MEMBER_SEEDS),
    "iot23v2_rows": 23145,
    "training_domains": "previously_exposed_development_data_only",
    "threshold": FIXED_CUTOFF,
    "estimator": ESTIMATOR,
    "new_production_model_approved": False,
}


def protocol_digest() -> str:
    return hashlib.sha256(
        json.dumps(PROTOCOL, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def load_real_unsw(archive: Path) -> list[FlowV2]:
    if archive.stat().st_size != SOURCE_EXPECTED_BYTES or digest(archive) != UNSW_SHA:
        raise ValueError("UNSW training ZIP SHA or size mismatch")
    originals = []
    with zipfile.ZipFile(archive) as zf:
        for member, seed in zip(MEMBERS, MEMBER_SEEDS):
            events, scan = read_reservoir(zf, member, SAMPLE_PER_MEMBER, seed)
            if len(events) != SAMPLE_PER_MEMBER or not scan:
                raise ValueError("UNSW family capture incomplete")
            originals.extend(events)
    if digest(archive) != UNSW_SHA:
        raise ValueError("UNSW data changed while training")
    records, _ = unique(originals)
    return [FlowV2.model_validate(e.model_dump()) for e in records]


def load_real_iot23(zeek: Path) -> list[FlowV2]:
    if zeek.stat().st_size != IOT_BYTES or digest(zeek) != IOT_SHA:
        raise ValueError("IoT-23v2 raw source SHA or size mismatch")
    records = []
    seen = set()
    with zeek.open("r", encoding="utf-8") as file:
        header = False
        for raw in file:
            if raw.startswith("#fields\t"):
                _require_header(raw)
                header = True
                continue
            if raw.startswith("#"):
                continue
            if not header:
                raise ValueError("missing authoritative v2 Zeek schema")
            cells = raw.rstrip("\r\n").split("\t")
            if len(cells) != 21:
                raise ValueError("malformed IoT-23v2 row")
            labels = re.split(r"\s{2,}", cells[20].strip())
            if len(labels) != 3 or labels[1] not in ("Benign", "Malicious"):
                raise ValueError("not an authentic labeled IoT-23v2 record")
            record = dict(zip(COLUMNS, cells[:20]))
            event = from_zeek_v2(record).model_copy(update={
                "label": "benign" if labels[1] == "Benign" else "anomaly"
            })
            # Strict in-dataset repetition suppression, no flow ID published.
            key = (event.uid, event.timestamp, str(event.src_ip),
                   str(event.dst_ip), event.src_port, event.dst_port, event.proto)
            if key in seen:
                raise ValueError("duplicate IoT training flow identity")
            seen.add(key)
            records.append(event)
    if len(records) != 23145 or digest(zeek) != IOT_SHA:
        raise ValueError("IoT-23v2 row support or raw source integrity changed")
    return records


def fit(exposed_source: list[FlowV2], exposed_iot: list[FlowV2]) -> tuple[dict, dict]:
    if len(exposed_source) < 15000 or len(exposed_iot) != 23145:
        raise ValueError("missing one exposed development source family")
    if not all(isinstance(e, FlowV2) for e in exposed_source + exposed_iot):
        raise ValueError("only versioned V2 flow records can train V2 estimator")
    if any(e.source != "zeek" for e in exposed_iot):
        raise ValueError("IoT source is not genuine Zeek")
    unsw = Counter(e.label for e in exposed_source)
    iot = Counter(e.label for e in exposed_iot)
    if any(c[label] < 100 for c in (unsw, iot) for label in ("benign", "anomaly")):
        raise ValueError("authentic supervised classes absent in either family")
    source = exposed_source + exposed_iot
    encoder = DictVectorizer(sparse=False)
    x = encoder.fit_transform([features_v2(e) for e in source])
    labels = np.asarray([int(e.label == "anomaly") for e in source], dtype=int)
    estimator = RandomForestClassifier(**ESTIMATOR).fit(x, labels)
    if tuple(estimator.classes_) != (0, 1):
        raise ValueError("fit lost a genuine network class")
    bundle = {
        "schema_version": 2,
        "research_only": True,
        "production_approved": False,
        "feature_contract": V2_FEATURE_CONTRACT,
        "fixed_cutoff": FIXED_CUTOFF,
        "protocol_sha256": protocol_digest(),
        "source_zip_sha256": UNSW_SHA,
        "iot23_source_sha256": IOT_SHA,
        "scikit_learn_version": sklearn.__version__,
        "vectorizer": encoder,
        "estimator": estimator,
    }
    manifest = {
        "status": "mixed_exposed_source_v2_research_model_frozen",
        "research_only": True,
        "model_train_complete": True,
        "production_signed": False,
        "deployed_detector_modified": False,
        "independent_test_performed": False,
        "original_iot23_is_now_training_data": True,
        "model_selection_from_exposed_sources": True,
        "protocol": PROTOCOL,
        "protocol_sha256": protocol_digest(),
        "source_training_rows": len(exposed_source),
        "iot23_training_rows": len(exposed_iot),
        "total_training_rows": len(source),
        "source_class_support": {"benign": unsw["benign"], "anomaly": unsw["anomaly"]},
        "iot23_class_support": {"benign": iot["benign"], "anomaly": iot["anomaly"]},
        "iot23_rows_with_missing_numeric": sum(
            any(getattr(e, f) is None for f in (
                "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"
            )) for e in exposed_iot
        ),
        "training_feature_count": x.shape[1],
        "dependency_versions": {
            "python": platform.python_version(), "sklearn": sklearn.__version__,
            "numpy": np.__version__, "joblib": joblib.__version__,
        },
        "limitations": [
            "Both training families are exposed prior model-development datasets.",
            "Zero untouched source-independent holdouts evaluated by this freeze.",
            "Source IP/host ledger and analyst-reviewed independent deployment not certified.",
            "Zeek payload bytes and UNSW flow counters may not have equivalent semantics.",
            "Model is unsigned research-only and incompatible with active IF detector.",
        ],
    }
    return bundle, manifest


def freeze(unsw: Path, iot: Path, artifact: Path, report: Path) -> dict:
    if artifact.exists() or report.exists():
        raise ValueError("refuse overwriting research model or manifest")
    source = load_real_unsw(unsw)
    zeek = load_real_iot23(iot)
    bundle, manifest = fit(source, zeek)
    artifact.parent.mkdir(parents=True, exist_ok=True)
    # Mode 0600: pickle is code-executable; do not accept untrusted bytes.
    fd = os.open(artifact, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out:
        joblib.dump(bundle, out, compress=3)
    frozen = digest(artifact)
    try:
        # Verify locally-produced, out-of-band SHA-pinned bytes before loading.
        if digest(artifact) != frozen:
            raise ValueError("model bundle changed after fit")
        restored = joblib.load(artifact)
        if (restored["schema_version"] != 2 or
                restored["protocol_sha256"] != protocol_digest() or
                restored["scikit_learn_version"] != sklearn.__version__):
            raise ValueError("model serialization protocol mismatch")
        input_sample = [source[0], source[-1], zeek[0], zeek[-1]]
        original = bundle["estimator"].predict_proba(
            bundle["vectorizer"].transform([features_v2(e) for e in input_sample])
        )
        replay = restored["estimator"].predict_proba(
            restored["vectorizer"].transform([features_v2(e) for e in input_sample])
        )
        if not np.array_equal(original, replay):
            raise ValueError("frozen V2 predictions differ after reloading")
        manifest["artifact_sha256"] = frozen
        manifest["artifact_bytes"] = artifact.stat().st_size
        report.parent.mkdir(parents=True, exist_ok=True)
        with report.open("x", encoding="utf-8") as destination:
            json.dump(manifest, destination, indent=2, sort_keys=True, allow_nan=False)
            destination.write("\n")
    except Exception:
        artifact.unlink(missing_ok=True)
        raise
    return manifest


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--unsw-zip", type=Path, required=True)
    p.add_argument("--iot23v2-labeled", type=Path, required=True)
    p.add_argument("--unsigned-model", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    a = p.parse_args()
    output = freeze(a.unsw_zip, a.iot23v2_labeled, a.unsigned_model, a.manifest)
    print(json.dumps({
        "status": output["status"],
        "total_training_rows": output["total_training_rows"],
        "iot23_missing_numeric": output["iot23_rows_with_missing_numeric"],
        "artifact_sha256": output["artifact_sha256"],
        "independent_test_performed": False,
        "production_signed": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
