"""Bounds and source-only selection invariants for full-archive MQTT repair."""
from __future__ import annotations

from networkpulse.evaluation import iot_sfc_full_day_mqtt_fit as full
from networkpulse.evaluation import iot_sfc_mqtt_repair as repair


def test_reservoir_is_bounded_and_deterministic():
    first = full.Reservoir(20, 1729)
    second = full.Reservoir(20, 1729)
    for value in range(200):
        first.add(value)
        second.add(value)
    assert first.seen == 200
    assert len(first.items) == 20
    assert first.items == second.items
    assert len(set(first.items)) == 20


def test_small_buckets_retain_all_rows():
    pool = full.Reservoir(5, 2)
    for i in range(3):
        pool.add(i)
    assert pool.items == [0, 1, 2]


def test_family_is_safe_bounded_taxonomy():
    assert full.family_bin({"type_of_attack": "MQTT_MALFORMED"}, 1) == "mqtt_malformed"
    assert full.family_bin({"type_of_attack": "MQTT_BRUTE_FORCE"}, 1) == "mqtt_brute_force"
    assert full.family_bin({"type_of_attack": "192.0.2.1"}, 1) == "other_attack_family"
    assert full.family_bin({"type_of_attack": "MQTT_MALFORMED"}, 0) == "benign"


def test_source_date_fence_and_capacity():
    assert full.FIT_FIRST.isoformat() == "2025-04-03"
    assert full.FIT_LAST.isoformat() == "2025-04-08"
    assert full.DEV_DAY.isoformat() == "2025-04-10"
    assert full.DEV_DAY < full.locked.TEST_DAYS[0]
    assert full.FIT_ATTACK_CAP_DAY_FAMILY < full.DEV_ATTACK_CAP_FAMILY


def test_diagnostic_or_restores_either_model_positive_without_recutting_frozen():
    assert repair.locked.CUTOFF == 0.90
    assert repair.frozen_or_repair(0.91, 0.02, 0.80) is True
    assert repair.frozen_or_repair(0.02, 0.81, 0.80) is True
    assert repair.frozen_or_repair(0.90, 0.80, 0.80) is True
    assert repair.frozen_or_repair(0.89, 0.79, 0.80) is False
    assert repair.frozen_or_repair(0.50, 0.79, 0.80) is False
