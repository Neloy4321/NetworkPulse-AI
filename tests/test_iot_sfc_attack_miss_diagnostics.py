"""Privacy and metric invariants for exposed-date diagnostic replay."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from ipaddress import ip_address
from types import SimpleNamespace

import pytest

from networkpulse.evaluation import iot_sfc_attack_miss_diagnostics as diagnose


def flow(**kwargs):
    values = dict(
        dst_port=1883, proto="tcp", conn_state="S1", duration=1.0,
        orig_bytes=100, resp_bytes=None, orig_pkts=2, resp_pkts=None,
        src_ip=ip_address("192.0.2.1"), dst_ip=ip_address("198.51.100.1"),
        timestamp=datetime(2025, 4, 15, tzinfo=timezone.utc),
        uid="not_for_export", src_port=54321,
    )
    values.update(kwargs)
    return SimpleNamespace(**values)


def test_categories_do_not_echo_identifiers():
    for secret in ("1.2.3.4", "john@corp.com", "abc\\user", "x" * 49):
        assert diagnose.category(secret) == "unclassified"
    assert diagnose.category("Mirai_TCP") == "mirai_tcp"


def test_only_bounded_safe_aggregate_slices():
    values = diagnose.row_slices(
        flow(), {"type_of_attack": "Mirai_TCP", "uid": "secret"},
        "2025-04-15", 1,
    )
    assert values == {
        "day": "2025-04-15", "protocol": "tcp", "service": "port_1883",
        "connection_state": "s1", "missingness": "00101",
        "attack_family": "mirai_tcp",
        "day_attack_family": "2025-04-15:mirai_tcp",
    }
    assert "secret" not in str(values)
    assert "192.0.2.1" not in str(values)


def test_threshold_tradeoff_is_diagnostic_not_candidate_selection():
    totals = Counter()
    slices = defaultdict(lambda: defaultdict(Counter))
    thresholds = defaultdict(Counter)
    diagnose.record(totals, slices, thresholds, flow=flow(),
                    row={"type_of_attack": "Family"}, day="2025-04-15",
                    label=1, score=0.89)
    diagnose.record(totals, slices, thresholds, flow=flow(),
                    row={"type_of_attack": "-"}, day="2025-04-15",
                    label=0, score=0.74)
    assert totals == Counter({"fn": 1, "tn": 1})
    assert thresholds[0.7] == Counter({"tp": 1, "fp": 1})
    assert thresholds[0.9] == totals
    assert diagnose.PINNED_APR15["fn"] == 419


def test_nan_probability_fails_closed():
    with pytest.raises(ValueError, match="probability"):
        diagnose.record(Counter(), defaultdict(lambda: defaultdict(Counter)),
                        defaultdict(Counter), flow=flow(), row={},
                        day="2025-04-15", label=1, score=float("nan"))


def test_rare_slices_are_aggregated_without_raw_categories():
    slices = defaultdict(lambda: defaultdict(Counter))
    slices["attack_family"]["rare_1"] = Counter({"fn": 2})
    slices["attack_family"]["rare_2"] = Counter({"tp": 3})
    slices["attack_family"]["common"] = Counter({"fn": 8, "tp": 10})
    result = diagnose.publish_slices(slices)["attack_family"]
    assert set(result) == {"common", "other_rare_categories"}
    assert result["other_rare_categories"]["attack"] == 5
