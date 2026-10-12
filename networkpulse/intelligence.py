"""Explainable aggregated flow-behavior context, not attack attribution."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from networkpulse.storage import NetworkEvent


def host_behavior(session: Session, *, since: datetime | None = None,
                  limit_flows: int = 20000, max_hosts: int = 50,
                  scan_ports: int = 12) -> dict:
    """Bounded per-source aggregates; does not read packet payloads.

    Includes a scanning-LIKE heuristic. It does not identify attacks, benign
    vulnerability scanners, authorization status or the true identity of hosts.
    """
    if since is None:
        # Use latest available event timestamp to support historical demo replay.
        last = session.scalars(select(NetworkEvent.timestamp).order_by(
            NetworkEvent.timestamp.desc()).limit(1)).first()
        since = (last - timedelta(hours=1)) if last is not None else datetime.now(timezone.utc)
    if scan_ports < 2 or not 1 <= max_hosts <= 200 or not 1 <= limit_flows <= 100000:
        raise ValueError("invalid aggregation limits")
    flows = session.scalars(select(NetworkEvent)
        .where(NetworkEvent.timestamp >= since)
        .order_by(NetworkEvent.timestamp.desc()).limit(limit_flows)).all()
    groups: dict[str, list[NetworkEvent]] = defaultdict(list)
    for flow in flows:
        groups[flow.src_ip].append(flow)
    rows = []
    for src, events in groups.items():
        ports = Counter(e.dst_port for e in events)
        anomalous = sum(bool(e.anomalous) for e in events)
        rows.append({
            "source_ip": src,
            "flows": len(events),
            "anomalous": anomalous,
            "anomaly_rate": round(anomalous / len(events), 4),
            "distinct_destination_ports": len(ports),
            "distinct_destination_hosts": len({e.dst_ip for e in events}),
            "top_destination_ports": [{"port": p, "count": n} for p, n in ports.most_common(5)],
            "scanning_like": len(ports) >= scan_ports,
        })
    rows.sort(key=lambda r: (-r["anomalous"],-r["flows"],r["source_ip"]))
    return {"window_start": since.isoformat(),"flow_count":len(flows),
            "host_count":len(groups),"hosts":rows[:max_hosts],
            "limitations":"Windowed metadata aggregates and heuristics; not proof of malicious activity."}
