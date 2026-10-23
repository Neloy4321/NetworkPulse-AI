"""Read-only provenance corroboration for official IoT-SFC attack sessions.

The producer's attack-window metadata is NOT independent human ground truth.
This module never exports device addresses, flow IDs or individual records.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from networkpulse.evaluation.iot_sfc_full_day_mqtt_fit import APPROVED_FAMILIES

OFFICIAL_LOG_SHA256 = "c9ebc4a4760a84bc9c744c25cdbd51f5ae9b9259b03a983b5a5e9dcce8f612d0"
OFFICIAL_LOG_MD5 = "53d98e593afe9f2dd75d8f3ccecf81a7"
EXPECTED_SESSIONS = 302


@dataclass(frozen=True)
class AttackSession:
    family: str
    start_utc: datetime
    end_utc: datetime
    source: str
    destinations: frozenset[str]


def _parse_utc(value: str) -> datetime:
    parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%SZ")
    return parsed.replace(tzinfo=timezone.utc)


def parse_sessions(raw: bytes) -> tuple[AttackSession, ...]:
    """Official file has comment lines preceding a JSON array."""
    stripped = b"\n".join(line for line in raw.splitlines()
                         if not line.lstrip().startswith(b"#"))
    records = json.loads(stripped)
    if not isinstance(records, list):
        raise ValueError("Official attack sessions must be a JSON array")
    sessions = []
    for item in records:
        if not isinstance(item, dict):
            raise ValueError("Unexpected session structure")
        family = str(item["attack_type"]).lower()
        if family not in APPROVED_FAMILIES:
            raise ValueError("Unexpected attack family in official session log")
        start = _parse_utc(item["start_time_utc"])
        end = _parse_utc(item["end_time_utc"])
        if end < start:
            raise ValueError("Negative official attack window duration")
        source = item["source"]
        destinations = item.get("destinations") or []
        if (not isinstance(source, str) or not source
                or not isinstance(destinations, list)
                or any(not isinstance(x, str) for x in destinations)):
            raise ValueError("Unexpected private endpoint metadata structure")
        sessions.append(AttackSession(family, start, end, source,
                                      frozenset(destinations)))
    return tuple(sessions)


def load_exact_official_log(path: Path) -> tuple[AttackSession, ...]:
    raw = path.read_bytes()
    if (hashlib.sha256(raw).hexdigest() != OFFICIAL_LOG_SHA256
            or hashlib.md5(raw, usedforsecurity=False).hexdigest() != OFFICIAL_LOG_MD5):
        raise ValueError("Official IoT-SFC attack-session log hash mismatch")
    sessions = parse_sessions(raw)
    if len(sessions) != EXPECTED_SESSIONS:
        raise ValueError("Official attack-session count changed")
    return sessions


class Corroborator:
    """Aggregate source-relative time corroboration; no label correction."""

    def __init__(self, sessions: tuple[AttackSession, ...]):
        self.by_family = defaultdict(list)
        for session in sessions:
            self.by_family[session.family].append(session)
        self.totals = Counter()

    def observe_attack(self, *, family: str, timestamp: datetime,
                       src_ip: str, dst_ip: str) -> None:
        if timestamp.tzinfo is None:
            raise ValueError("Naive timestamp in provenance audit")
        self.totals["producer_attack_rows"] += 1
        candidates = [session for session in self.by_family.get(family, ())
                      if session.start_utc <= timestamp <= session.end_utc]
        if not candidates:
            self.totals["no_same_family_time_window"] += 1
            return
        self.totals["same_family_time_window"] += 1
        if any(src_ip == s.source or dst_ip == s.source for s in candidates):
            self.totals["recorded_attacker_endpoint_present"] += 1
        if any(src_ip in s.destinations or dst_ip in s.destinations for s in candidates):
            self.totals["recorded_target_endpoint_present"] += 1

    def aggregate_only(self) -> dict:
        """Counts are diagnostic, not independent producer-label verification."""
        return {
            "official_sessions": sum(map(len, self.by_family.values())),
            "producer_labels_independently_adjudicated": False,
            "attack_window_match_is_ground_truth": False,
            "aggregate_counts": dict(sorted(self.totals.items())),
        }
