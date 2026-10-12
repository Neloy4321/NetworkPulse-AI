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


def correlate_windows(session: Session, *, window_minutes: int = 10,
                      min_destinations: int = 4, min_ports: int = 4,
                      max_flows: int = 20000, max_results: int = 100) -> list[dict]:
    """Deterministic multi-flow correlation of scanning-LIKE metadata patterns.

    No threat claim, attribution, IP reputation or intrusion labels are inferred.
    """
    if not 1 <= window_minutes <= 120 or min_destinations < 2 or min_ports < 2:
        raise ValueError('invalid correlation window and thresholds')
    if not 1 <= max_flows <= 100000 or not 1 <= max_results <= 1000:
        raise ValueError('invalid correlation bounds')
    from collections import defaultdict
    flows = session.scalars(select(NetworkEvent).order_by(NetworkEvent.timestamp.desc())
                            .limit(max_flows)).all()
    grouped = defaultdict(list)
    span = window_minutes * 60
    for event in flows:
        # Align window boundaries using epoch seconds, not local timezone.
        stamp = event.timestamp
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        bucket = int(stamp.timestamp()) // span
        grouped[(event.src_ip, bucket)].append(event)
    output = []
    for (source, bucket), rows in grouped.items():
        destinations = len({r.dst_ip for r in rows})
        ports = len({r.dst_port for r in rows})
        if destinations < min_destinations and ports < min_ports:
            continue
        output.append({
            'src_ip': source, 'window_start_utc': datetime.fromtimestamp(bucket * span,
                                                                         tz=timezone.utc).isoformat(),
            'flow_count': len(rows), 'destination_count': destinations,
            'port_count': ports, 'flagged_flows': sum(bool(r.anomalous) for r in rows),
            'scanning_like': ports >= min_ports,
            'distributed_targeting_like': destinations >= min_destinations,
            'confidence': 'heuristic_only',
        })
    return sorted(output, key=lambda x: (-x['flagged_flows'], -x['flow_count'],
                                         x['src_ip'], x['window_start_utc']))[:max_results]
