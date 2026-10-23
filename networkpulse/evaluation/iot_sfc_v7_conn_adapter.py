"""Versioned IoT-SFC v7 conn.log-only adapter for the immutable FlowV2 contract.

Research preparation only: never score, tune, unpickle, infer true labels,
or claim independent reviewer approval. Original 87-column header is pinned.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from networkpulse.feature_contract_v2 import FlowV2, from_zeek_v2
from networkpulse.evaluation.iot_sfc_preregistration import MODEL_SHA, TARGET_SHA

HEADER_EVIDENCE = (
    Path(__file__).resolve().parents[2]
    / "docs/P0_IOT_SFC_V2_VERIFIED_HEADER_EVIDENCE.json"
)
MODEL_CUTOFF = 0.20
ALIAS_MAP = {
    "orig_h": "id.orig_h",
    "orig_p": "id.orig_p",
    "resp_h": "id.resp_h",
    "resp_p": "id.resp_p",
}
REQUIRED = (
    "ts", "orig_h", "orig_p", "resp_h", "resp_p", "proto", "log_type",
)
OPTIONAL = (
    "uid", "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "conn_state",
)
PROVENANCE = ("attack", "type_of_attack", "label_source", "window_id")


class RowNotEligible(ValueError):
    """Category-only failure; must never embed raw IP/UID/row values."""


def _present(value: object) -> bool:
    return value is not None and str(value).strip() not in ("", "-", "(empty)", "(unset)")


def verify_exact_header(columns: list[str]) -> dict:
    """Only header identity; does NOT establish real Zeek row semantics."""
    evidence = json.loads(HEADER_EVIDENCE.read_text(encoding="utf-8"))
    if (evidence["source_original_sha256"] != TARGET_SHA
            or evidence["model_sha256"] != MODEL_SHA
            or evidence["decision_threshold"] != MODEL_CUTOFF
            or len(columns) != 87
            or columns != evidence["csv_header_exact"]):
        raise ValueError("IoT-SFC v7 schema/model/threshold pin mismatch")
    return {
        "header_locked": True,
        "model_sha256": MODEL_SHA,
        "fixed_threshold": MODEL_CUTOFF,
        "feature_contract": "missingness_aware_flow_v2",
        "sensor_row_semantics_confirmed": False,
        "producer_labels_independently_reviewed": False,
        "production_ml_accepted": False,
    }


def conn_log_to_flow_v2(row: Mapping[str, str]) -> FlowV2:
    """Strict candidate mapping: non-conn events and invalid identities are denied.

    Even a valid FlowV2 is only an *unlabeled candidate* pending provenance
    and clock/direction verification against raw Zeek logs. No model is run.
    """
    if not isinstance(row, Mapping):
        raise RowNotEligible("not_a_mapping")
    if any(name not in row for name in REQUIRED):
        raise RowNotEligible("missing_required_column")
    if str(row["log_type"]).strip() != "conn.log":
        raise RowNotEligible("not_explicit_conn_log")
    if any(not _present(row.get(name)) for name in REQUIRED if name != "log_type"):
        raise RowNotEligible("missing_required_identity")
    if not all(alias not in row for alias in ALIAS_MAP.values()):
        raise RowNotEligible("ambiguous_mixed_native_and_merged_columns")
    source = {key: row[key] for key in REQUIRED if key not in ("log_type",)}
    source.update({ALIAS_MAP[name]: row[name] for name in ALIAS_MAP})
    for key in OPTIONAL:
        if key in row:
            source[key] = row[key]
    # Non-flow fields, potential labels, IPs/UID and source discriminator
    # cannot accidentally reach the frozen model's vectorizer as features.
    try:
        flow = from_zeek_v2(source)
    except (ValueError, KeyError, TypeError, OverflowError) as exc:
        raise RowNotEligible("invalid_native_zeek_conn_values") from None
    if flow.label is not None:
        raise RowNotEligible("target_label_leaked_into_inference")
    return flow


@dataclass(frozen=True)
class ProducerLabelEvidence:
    """Unreviewed binary producer label; *not* ground truth approval."""
    producer_class: int
    attack_family_present: bool
    label_source_present: bool
    window_id_present: bool
    independence_confirmed: bool = False
    independently_reviewed: bool = False


def inspect_untrusted_producer_label(row: Mapping[str, str]) -> ProducerLabelEvidence:
    """Never pass output into model.fit, predict or accepted evidence unreviewed."""
    if "attack" not in row or "type_of_attack" not in row:
        raise RowNotEligible("missing_producer_label_columns")
    binary = str(row["attack"]).strip()
    if binary not in ("0", "1"):
        raise RowNotEligible("invalid_binary_producer_label")
    family = _present(row.get("type_of_attack"))
    provenance = _present(row.get("label_source"))
    window = _present(row.get("window_id"))
    if binary == "1" and (not family or not provenance or not window):
        raise RowNotEligible("missing_attack_provenance_fields")
    # Publisher-reported window associations do not independently certify
    # attackers, traffic direction, benign intervals or site independence.
    return ProducerLabelEvidence(
        producer_class=int(binary),
        attack_family_present=family,
        label_source_present=provenance,
        window_id_present=window,
    )
