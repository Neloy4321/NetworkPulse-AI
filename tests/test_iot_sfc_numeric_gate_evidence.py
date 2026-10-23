"""Recalculate real IoT-SFC v7 numerical gate and guard operator approval."""
from __future__ import annotations

import copy
import json

import pytest

from networkpulse.evaluation import iot_sfc_numeric_gate_evidence as audit


@pytest.fixture
def evidence():
    return json.loads(audit.DEFAULT.read_text(encoding="utf-8"))


def test_original_research_numerical_gate_pass_is_exactly_reproducible(evidence):
    result = audit.verify(evidence)
    assert result["aggregate_numeric_research"] == "PASS"
    assert result["fpr_upper_95"] < 0.05
    assert result["recall_lower_95"] > 0.80
    assert result["fpr"] > .04
    assert result["recall"] > .98
    assert result["operational_ml_p0"] == "NO_GO"


def test_attack_day_fpr_exceeds_gate_and_cannot_disappear(evidence):
    outcome = audit.verify(evidence)
    assert outcome["day_2025_04_13_fpr_upper_95"] > .07
    assert evidence["results"]["distinct_days_with_both_classes"] == 1
    assert evidence["results"]["per_day_robustness_gate_pass"] is False
    assert evidence["results"]["unseen_training_hostpair_attack_support"] == 0


@pytest.mark.parametrize("field,value", [
    ("fp", 0), ("tp", 216533), ("tn", 125226), ("fn", 0),
])
def test_confusion_manipulation_fails(evidence, field, value):
    evidence["results"]["confusion"][field] = value
    with pytest.raises(ValueError):
        audit.verify(evidence)


@pytest.mark.parametrize("key,value", [
    ("fpr", 0.00001), ("recall", 1.0),
    ("fpr_wilson_upper_95", 0.0001),
    ("recall_wilson_lower_95", 1.0),
])
def test_misreported_metrics_fail(evidence, key, value):
    evidence["results"][key] = value
    with pytest.raises(ValueError):
        audit.verify(evidence)


def test_any_false_production_promotion_fails(evidence):
    for prop, changed in [
        ("production_p0", "GO"),
        ("independent_field_site", "VERIFIED"),
        ("signed_operator_model", "SIGNED"),
        ("human_label_ground_truth", "VERIFIED"),
    ]:
        candidate = copy.deepcopy(evidence)
        candidate["release_decision"][prop] = changed
        with pytest.raises(ValueError):
            audit.verify(candidate)


@pytest.mark.parametrize("location,property,value", [
    ("model", "fixed_cutoff", .2),
    ("model", "research_only", False),
    ("model", "artifact_sha256", "0"*64),
    ("source", "candidate_testing_data_used_for_selection", True),
    ("source", "training_dev_shared_hostpair_protocol_count", 0),
    ("provenance", "original_test_workflow_run", 1),
])
def test_source_and_runtime_identity_pins_are_immutable(
    evidence, location, property, value,
):
    evidence[location][property] = value
    with pytest.raises(ValueError):
        audit.verify(evidence)


def test_partial_support_day_must_not_be_counted_as_attack_recall(evidence):
    assert evidence["results"]["per_day"]["2025-04-12"]["attack"] == 0
    assert evidence["results"]["per_day"]["2025-04-14"]["benign"] == 1
    evidence["results"]["distinct_days_with_both_classes"] = 3
    with pytest.raises(ValueError):
        audit.verify(evidence)
