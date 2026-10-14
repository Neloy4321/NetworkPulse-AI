"""Operational SQL-backed source behavior, over real committed NetworkEvent rows.

Used by authenticated API over database events written by HTTP and Redis
Streams. No sampled input rows, fake events or in-memory top-N truncation.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone

from sqlalchemy import BigInteger, case, cast, distinct, func, select
from sqlalchemy.orm import Session

from networkpulse.storage import NetworkEvent


def activity_windows(
    session: Session, *, window_minutes: int = 5,
    lookback_minutes: int = 60, until: datetime | None = None,
    src_ip: str | None = None, limit: int = 30, offset: int = 0,
    min_distinct_ports: int = 12, min_distinct_destinations: int = 8,
    burst_flows_per_minute: int = 120,
) -> dict:
    """Full-data 1/5-minute UTC buckets; time and result limits are explicit.

    Existing event-key uniqueness makes HTTP/Redis retries idempotent.
    Query cost still scales with matching flow rows; monitor PostgreSQL p95
    and materialize rollups if traffic volume requires it.
    """
    if window_minutes not in (1, 5):
        raise ValueError("window_minutes must be 1 or 5")
    if not 1 <= lookback_minutes <= 1440 or not 1 <= limit <= 100 or not 0 <= offset <= 10000:
        raise ValueError("invalid lookback or page")
    if not 2 <= min_distinct_ports <= 65536 or not 2 <= min_distinct_destinations <= 10000:
        raise ValueError("invalid behavioral threshold")
    if not 10 <= burst_flows_per_minute <= 100000:
        raise ValueError("invalid burst threshold")
    end = until or datetime.now(timezone.utc)
    if end.tzinfo is None or end.utcoffset() is None:
        raise ValueError("until must contain timezone")
    end = end.astimezone(timezone.utc)
    start = end - timedelta(minutes=lookback_minutes)
    address = str(ipaddress.ip_address(src_ip)) if src_ip else None
    seconds = window_minutes * 60
    # FLOOR avoids PostgreSQL rounding CAST(numeric AS integer).
    bucket = cast(func.floor(func.extract("epoch", NetworkEvent.timestamp) / seconds), BigInteger)
    query = (
        select(
            (bucket * seconds).label("bucket_epoch"),
            NetworkEvent.src_ip.label("source_ip"),
            func.count(NetworkEvent.id).label("flow_count"),
            func.count(distinct(NetworkEvent.dst_port)).label("destination_ports"),
            func.count(distinct(NetworkEvent.dst_ip)).label("destination_hosts"),
            func.sum(NetworkEvent.orig_bytes + NetworkEvent.resp_bytes).label("total_bytes"),
            func.sum(NetworkEvent.orig_pkts + NetworkEvent.resp_pkts).label("total_packets"),
            func.sum(case((NetworkEvent.anomalous.is_(True), 1), else_=0)).label("flagged_flows"),
            func.sum(case((NetworkEvent.resp_pkts == 0, 1), else_=0)).label("no_response_flows"),
        )
        .where(NetworkEvent.timestamp >= start, NetworkEvent.timestamp <= end)
        .group_by(bucket, NetworkEvent.src_ip)
        .order_by(bucket.desc(), func.count(NetworkEvent.id).desc(), NetworkEvent.src_ip.asc())
        .offset(offset).limit(limit + 1)
    )
    if address:
        query = query.where(NetworkEvent.src_ip == address)
    fetched = session.execute(query).mappings().all()
    windows = []
    for raw in fetched[:limit]:
        count = int(raw["flow_count"])
        ports = int(raw["destination_ports"])
        hosts = int(raw["destination_hosts"])
        window_start = datetime.fromtimestamp(int(raw["bucket_epoch"]), timezone.utc)
        patterns = []
        if ports >= min_distinct_ports:
            patterns.append("port_sweep_like")
        if hosts >= min_distinct_destinations:
            patterns.append("destination_fanout_like")
        if count >= burst_flows_per_minute * window_minutes:
            patterns.append("connection_burst_like")
        windows.append({
            "source_ip": raw["source_ip"],
            "window_start_utc": window_start.isoformat(),
            "window_end_utc": (window_start + timedelta(seconds=seconds)).isoformat(),
            "window_minutes": window_minutes,
            "flow_count": count,
            "distinct_destination_ports": ports,
            "distinct_destination_hosts": hosts,
            "total_bytes": int(raw["total_bytes"]),
            "total_packets": int(raw["total_packets"]),
            "flagged_flows": int(raw["flagged_flows"]),
            "no_response_flows": int(raw["no_response_flows"]),
            "flagged_fraction": round(int(raw["flagged_flows"]) / count, 4),
            "flows_per_minute": round(count / window_minutes, 2),
            "patterns": patterns,
            "partial_window": window_start < start or window_start + timedelta(seconds=seconds) > end,
        })
    return {
        "window_minutes": window_minutes,
        "range_start_utc": start.isoformat(),
        "range_end_utc": end.isoformat(),
        "source_ip_filter": address,
        "limit": limit,
        "offset": offset,
        "has_more": len(fetched) > limit,
        "windows": windows,
        "interpretation": "Full deduplicated persisted flow data in the UTC range. "
                          "Patterns are heuristic cues, not confirmed attacks. "
                          "Partial boundary windows and nominal per-minute rates need care.",
    }
