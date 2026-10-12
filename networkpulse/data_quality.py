"""Reproducible dataset quality and provenance report (no payload capture)."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from networkpulse.schemas import FlowEvent

CONTRACT_VERSION = 1


def fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1_048_576), b''):
            digest.update(block)
    return digest.hexdigest()


def quality_report(events: list[FlowEvent], *, source: str = 'memory',
                   source_sha256: str | None = None) -> dict:
    if not events:
        raise ValueError('at least one flow required')
    keys = [event.key() for event in events]
    seen = set(keys)
    stamps = [event.timestamp for event in events]
    raw_labels = Counter(event.label or 'unlabeled' for event in events)
    protocols = Counter(event.proto for event in events)
    origins = Counter(event.source for event in events)
    unique_src = {str(event.src_ip) for event in events}
    unique_dst = {str(event.dst_ip) for event in events}
    return {
        'feature_contract': CONTRACT_VERSION,
        'source': source,
        'source_sha256': source_sha256,
        'record_count': len(events),
        'unique_record_count': len(seen),
        'duplicate_count': len(events) - len(seen),
        'chronological_order': all(a <= b for a, b in zip(stamps, stamps[1:])),
        'earliest_utc': min(stamps).astimezone(timezone.utc).isoformat(),
        'latest_utc': max(stamps).astimezone(timezone.utc).isoformat(),
        'unique_source_ips': len(unique_src),
        'unique_destination_ips': len(unique_dst),
        'protocols': dict(protocols),
        'sources': dict(origins),
        'labels': dict(raw_labels),
        'run_at_utc': datetime.now(timezone.utc).isoformat(),
        'disclaimer': 'Metadata quality only; labels and provenance are not independently verified.',
    }


def write_quality_report(events: list[FlowEvent], source: Path, output: Path) -> dict:
    report = quality_report(events, source=str(source), source_sha256=fingerprint(source))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report
