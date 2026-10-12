"""Defensive adapters for Zeek conn.log JSON, Suricata EVE flow and canonical JSONL.

Only flow metadata is parsed; packet content/payload is never required or persisted.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from networkpulse.schemas import FlowEvent


class SkipRecord(Exception):
    """An unrelated Suricata EVE record is intentionally skipped."""


def _n(value: Any) -> int:
    if value in (None, "-"):
        return 0
    return max(0, int(value))


def _f(value: Any) -> float:
    if value in (None, "-"):
        return 0.0
    return max(0.0, float(value))


def from_zeek(record: dict[str, Any]) -> FlowEvent:
    """Zeek: use JSON conn.log, not tab-delimited TSV or raw PCAP."""
    stamp = record["ts"]
    if isinstance(stamp, (int, float)):
        stamp = datetime.fromtimestamp(stamp, tz=timezone.utc)
    return FlowEvent(
        timestamp=stamp,
        source="zeek",
        uid=record.get("uid"),
        src_ip=record["id.orig_h"],
        dst_ip=record["id.resp_h"],
        src_port=_n(record.get("id.orig_p")),
        dst_port=_n(record.get("id.resp_p")),
        proto=record.get("proto", "other").lower(),
        duration=_f(record.get("duration")),
        orig_bytes=_n(record.get("orig_bytes")),
        resp_bytes=_n(record.get("resp_bytes")),
        orig_pkts=_n(record.get("orig_pkts")),
        resp_pkts=_n(record.get("resp_pkts")),
        conn_state=record.get("conn_state", "unknown"),
    )


def from_suricata(record: dict[str, Any]) -> FlowEvent:
    """Suricata: process only event_type='flow' from EVE JSON."""
    if record.get("event_type") != "flow":
        raise SkipRecord("not a flow event")
    flow = record["flow"]
    return FlowEvent(
        timestamp=record["timestamp"],
        source="suricata",
        uid=str(record.get("flow_id", "")) or None,
        src_ip=record["src_ip"],
        dst_ip=record["dest_ip"],
        src_port=_n(record.get("src_port")),
        dst_port=_n(record.get("dest_port")),
        proto=record.get("proto", "other").lower(),
        duration=_f(flow.get("age", 0)),
        orig_bytes=_n(flow.get("bytes_toserver")),
        resp_bytes=_n(flow.get("bytes_toclient")),
        orig_pkts=_n(flow.get("pkts_toserver")),
        resp_pkts=_n(flow.get("pkts_toclient")),
        conn_state=str(flow.get("state", "unknown")),
    )


def parse(record: dict[str, Any], fmt: str) -> FlowEvent:
    if fmt == "zeek":
        return from_zeek(record)
    if fmt == "suricata":
        return from_suricata(record)
    if fmt == "canonical":
        return FlowEvent.model_validate(record)
    raise ValueError("format must be zeek, suricata or canonical")


def iter_jsonl(path: Path, fmt: str) -> Iterator[FlowEvent]:
    """Fail with file/line context; skip unrelated Suricata EVE event types."""
    with path.open("rt", encoding="utf-8") as stream:
        for lineno, line in enumerate(stream, 1):
            if not line.strip():
                continue
            if len(line) > 1_000_000:
                raise ValueError(f"{path}:{lineno}: record too large")
            try:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("expected JSON object")
                yield parse(value, fmt)
            except SkipRecord:
                continue
            except (ValueError, KeyError, TypeError) as exc:
                raise ValueError(f"{path}:{lineno}: {exc}") from exc
