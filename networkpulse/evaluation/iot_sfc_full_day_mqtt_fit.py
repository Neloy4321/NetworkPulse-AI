"""Research MQTT repair with date/family-balanced FIT from the WHOLE source CSV.

Does not fit to or select on Apr 12-17 labels; those dates have been exposed
and are used afterward only to stress-check the experimental source model.
All host identities remain in process memory and are never exported.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import os
import random
import zipfile
from collections import Counter
from datetime import date, datetime, timezone
from itertools import islice
from pathlib import Path

import numpy as np

from networkpulse.evaluation import iot_sfc_locked_later_days as locked
from networkpulse.evaluation import iot_sfc_mqtt_repair as repair
from networkpulse.evaluation import iot_sfc_combined_uwf_external as uwf_external
from networkpulse.evaluation.iot_sfc_frozen_score import adapt_v7_conn
from networkpulse.evaluation.iot_sfc_v7_conn_adapter import (
    RowNotEligible, inspect_untrusted_producer_label, verify_exact_header,
)

FIT_FIRST = date(2025, 4, 3)
FIT_LAST = date(2025, 4, 8)
DEV_DAY = date(2025, 4, 10)
FIT_BENIGN_CAP_DAY = 5_000
FIT_ATTACK_CAP_DAY_FAMILY = 1_500
DEV_BENIGN_CAP_DAY = 10_000
DEV_ATTACK_CAP_FAMILY = 3_000
APPROVED_FAMILIES = frozenset((
    "httpflood", "hydrabruteforce", "botnetsim", "cameratapoc200attack",
    "mitmarpspoof", "mqtt_brute_force", "mqtt_dos", "mqtt_malformed",
    "mqtt_sniff", "mqtt_spoof", "scanning", "slowloris", "synflood", "udpflood",
))


def family_bin(row: dict, label: int) -> str:
    if not label:
        return "benign"
    proposed = str(row.get("type_of_attack") or "").strip().lower()
    return proposed if proposed in APPROVED_FAMILIES else "other_attack_family"


def identity_hash(flow) -> bytes:
    key = repair.group_key(flow)
    return hashlib.sha256("|".join(key).encode("utf-8")).digest()


class Reservoir:
    """Deterministic bounded uniformly sampled rows within one source bucket."""

    def __init__(self, cap: int, seed: int):
        self.cap = cap
        self.seen = 0
        self.random = random.Random(seed)
        self.items = []

    def add(self, value) -> None:
        self.seen += 1
        if len(self.items) < self.cap:
            self.items.append(value)
            return
        idx = self.random.randrange(self.seen)
        if idx < self.cap:
            self.items[idx] = value


def buckets_from_original(archive: Path):
    """One full, bounded-memory scan. Examine labels ONLY on source dates."""
    pools = {}
    fit_groups_all = set()
    stats = Counter()
    family_counts = Counter()
    eligible_days = Counter()
    with zipfile.ZipFile(archive, "r", allowZip64=True) as zf:
        members = zf.infolist()
        if (len(members) != 1 or members[0].filename != locked.DATA_MEM
                or members[0].file_size != 13_561_863_941
                or members[0].flag_bits & 1 or members[0].is_dir()):
            raise ValueError("Original ZIP member identity changed")
        with zf.open(members[0], "r") as raw:
            with io.TextIOWrapper(raw, encoding="utf-8-sig", newline="") as src:
                old = csv.field_size_limit()
                csv.field_size_limit(131_072)
                try:
                    reader = csv.reader(src, strict=True)
                    header = next(reader)
                    verify_exact_header(header)
                    cols = {k: header.index(k) for k in ("log_type", "ts")}
                    for cells in reader:
                        stats["raw_rows"] += 1
                        if len(cells) != len(header):
                            stats["bad_width"] += 1
                            continue
                        if cells[cols["log_type"]] != "conn":
                            continue
                        stats["native_conn_rows"] += 1
                        try:
                            timestamp = float(cells[cols["ts"]])
                            if not math.isfinite(timestamp):
                                continue
                            day = datetime.fromtimestamp(timestamp, timezone.utc).date()
                        except (OverflowError, ValueError, OSError):
                            continue
                        if not (FIT_FIRST <= day <= FIT_LAST or day == DEV_DAY):
                            continue
                        row = dict(zip(header, cells))
                        try:
                            flow = adapt_v7_conn(row)
                            label = inspect_untrusted_producer_label(row).producer_class
                        except RowNotEligible:
                            stats["source_ineligible"] += 1
                            continue
                        fam = family_bin(row, label)
                        region = "fit" if day <= FIT_LAST else "dev"
                        bucket = (region, day.isoformat(), fam)
                        family_counts["|".join(bucket)] += 1
                        eligible_days[day.isoformat()] += 1
                        if region == "fit":
                            fit_groups_all.add(identity_hash(flow))
                        if bucket not in pools:
                            cap = (FIT_BENIGN_CAP_DAY if fam == "benign"
                                   else FIT_ATTACK_CAP_DAY_FAMILY)
                            if region == "dev":
                                cap = (DEV_BENIGN_CAP_DAY if fam == "benign"
                                       else DEV_ATTACK_CAP_FAMILY)
                            seed_bytes = hashlib.sha256("|".join(bucket).encode()).digest()
                            pools[bucket] = Reservoir(
                                cap, repair.SEED + int.from_bytes(seed_bytes[:8], "big")
                            )
                        pools[bucket].add((flow, label, fam))
                finally:
                    csv.field_size_limit(old)
    flows, y, families = [], [], []
    dev_raw_sample, excluded_dev_groups = 0, 0
    retained = Counter()
    for bucket, reservoir in sorted(pools.items()):
        for flow, label, fam in reservoir.items:
            if bucket[0] == "dev":
                dev_raw_sample += 1
                if identity_hash(flow) in fit_groups_all:
                    excluded_dev_groups += 1
                    continue
            flows.append(flow)
            y.append(label)
            families.append(fam)
            retained["|".join(bucket)] += 1
    return flows, np.asarray(y, dtype=np.int8), families, {
        "source_scan": dict(stats),
        "source_days_all_eligible": dict(sorted(eligible_days.items())),
        "source_family_day_support": dict(sorted(family_counts.items())),
        "bounded_sample_by_family_day": dict(sorted(retained.items())),
        "raw_development_sample": dev_raw_sample,
        "development_fit_hostpair_overlap_excluded": excluded_dev_groups,
        "unique_fit_hostpair_protocol_hashes_in_memory_only": len(fit_groups_all),
        "late_test_labels_inspected_during_source_fit": False,
    }


def replay_exposed(archive, original, vectorizer, model, cutoff):
    with zipfile.ZipFile(archive, "r", allowZip64=True) as zf:
        with zf.open(locked.DATA_MEM, "r") as raw:
            with io.TextIOWrapper(raw, encoding="utf-8-sig", newline="") as src:
                previous = csv.field_size_limit()
                csv.field_size_limit(131_072)
                try:
                    reader = csv.reader(src, strict=True)
                    header = next(reader)
                    verify_exact_header(header)
                    # Exact immutable sample: drop first 450k source rows then
                    # read the following nine million in the locked scorer.
                    reader = islice(reader, locked.FIT_DEV_PREFIX_EXCLUDED, None)
                    return repair.stress(reader, header, original, vectorizer,
                                         model, cutoff)
                finally:
                    csv.field_size_limit(previous)


def run(archive: Path, original_path: Path, external_csv: Path | None = None):
    original = locked.verify_source_and_model(archive, original_path)
    flows, labels, families, ledger = buckets_from_original(archive)
    vectorizer, model, cutoff, choice = repair.fit_source(flows, labels, families)
    del flows, labels, families
    # This replays the already-exposed laboratory slice. The scorer also emits
    # a diagnostic-only OR with the unchanged historical frozen model to
    # measure complementary errors; neither rule is selected or certified here.
    stress = replay_exposed(archive, original, vectorizer, model, cutoff)
    fused = stress["frozen_or_repair_research_only"]
    if (fused["selection_is_independently_qualified"] is not False
            or fused["already_exposed_same_lab_labels"] is not True):
        raise ValueError("Research-only OR must never be marked qualified")
    # The model and fallback cutoff are already fixed before examining ANY
    # independent-source scores or labels. UWF was used previously only with
    # the historical frozen model, so this remains a research transfer stress.
    cross_source = (uwf_external.score(external_csv, original, vectorizer,
                                       model, cutoff)
                    if external_csv is not None else None)
    result = {
        "status": "P0_FULL_SOURCE_DATE_FAMILY_MQTT_RESEARCH_STRESS_ONLY",
        "original_source_sha256": locked.TARGET_SHA,
        "original_frozen_model_sha256": locked.MODEL_SHA,
        "training_source_dates": "2025-04-03_through_2025-04-08",
        "selection_source_date": "2025-04-10_group_disjoint",
        "resampling": "seeded_uniform_reservoir_per_day_class_source_only",
        "feature_contract": "missingness_aware_flow_v2_plus_stable_service_and_state_research",
        "source_ledger": ledger,
        "source_selection": choice,
        "exposed_stress": stress,
        "new_prospective_holdout_used": False,
        "independently_reviewed_flow_labels": False,
        "signed_or_deployed": False,
        "operational_ml_p0": "NO_GO",
    }
    if cross_source is not None:
        result["external_uwf_transfer_stress"] = cross_source
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--original-model", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--uwf-external-csv", type=Path)
    args = p.parse_args()
    if args.report.exists() or args.report.is_symlink():
        p.error("Refuse to overwrite diagnostic evidence")
    result = run(args.archive, args.original_model, args.uwf_external_csv)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.report, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as dest:
        json.dump(result, dest, sort_keys=True, indent=2, allow_nan=False)
        dest.write("\n")
    print(json.dumps({"source_fit": result["source_selection"]["source_fit"],
                      "stress": result["exposed_stress"]["candidate_combined"],
                      "operational_ml_p0": "NO_GO"}))


if __name__ == "__main__":
    main()
