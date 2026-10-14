"""Durable, database-atomic behavioral correlation for production flow ingestion.

A dedicated worker evaluates *completed* five-minute UTC windows over the
same PostgreSQL/SQLite NetworkEvent records used by API and Redis Streams.
One finding per (source IP, UTC window), combining multiple heuristic signals.
Database PK + UPSERT prevent duplicate incidents under overlapping workers.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import case, distinct, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from networkpulse.storage import BehaviorFinding, NetworkEvent, now_utc

WINDOW_MINUTES = 5
PAGE_SIZE = 200


def finding_id(source_ip: str, start: datetime) -> str:
    """Stable identity; never includes mutable metrics or model predictions."""
    if start.tzinfo is None or start.utcoffset() is None:
        raise ValueError("window timestamp must be timezone-aware")
    canonical = f"v1|{source_ip}|{start.astimezone(timezone.utc).isoformat()}|5"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def _severity(patterns: list[str], flagged: int) -> str:
    """Operator-prioritization heuristic; never a calibrated threat probability."""
    if len(patterns) >= 2 and flagged > 0:
        return "high"
    if len(patterns) >= 2 or flagged > 0:
        return "medium"
    return "low"


def materialize_findings(
    session: Session, *, until: datetime | None = None,
    lookback_minutes: int = 30, lateness_minutes: int = 2,
    min_ports: int = 12, min_destinations: int = 8,
    burst_per_minute: int = 120, max_candidates: int = 10000,
) -> dict:
    """Idempotently correlate persisted flows in finalized UTC windows.

    Historical replay uses an explicitly supplied until time and lateness=0.
    Live worker runs continuously with a configurable watermark (default 2m).
    Late events within the lookback can monotonically enrich existing findings;
    status and assignment are never reset by an overlapping worker.
    """
    if lookback_minutes % 5 or not 5 <= lookback_minutes <= 1440:
        raise ValueError("lookback_minutes must be a multiple of 5 in 5..1440")
    if not 0 <= lateness_minutes <= 60:
        raise ValueError("lateness_minutes must be 0..60")
    if not 2 <= min_ports <= 65536 or not 2 <= min_destinations <= 10000:
        raise ValueError("invalid distinct-count threshold")
    if not 10 <= burst_per_minute <= 100000:
        raise ValueError("invalid burst rate")
    if not 100 <= max_candidates <= 100000:
        raise ValueError("invalid candidate cap")
    end = until or datetime.now(timezone.utc)
    if end.tzinfo is None or end.utcoffset() is None:
        raise ValueError("until must include timezone")
    watermark = end.astimezone(timezone.utc) - timedelta(minutes=lateness_minutes)
    boundary = datetime.fromtimestamp(
        (int(watermark.timestamp()) // 300) * 300, tz=timezone.utc
    )
    first = boundary - timedelta(minutes=lookback_minutes)
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        insert_fn = pg_insert
    elif dialect == "sqlite":
        insert_fn = sqlite_insert
    else:
        raise ValueError("Behavior correlation requires PostgreSQL or SQLite")
    candidates = 0
    completed = 0
    for number in range(lookback_minutes // WINDOW_MINUTES):
        start = first + timedelta(minutes=number * WINDOW_MINUTES)
        stop = start + timedelta(minutes=WINDOW_MINUTES)
        cursor = None
        while True:
            count = func.count(NetworkEvent.id)
            distinct_ports = func.count(distinct(NetworkEvent.dst_port))
            distinct_hosts = func.count(distinct(NetworkEvent.dst_ip))
            query = (
                select(
                    NetworkEvent.src_ip.label("source_ip"),
                    count.label("flow_count"),
                    distinct_ports.label("ports"),
                    distinct_hosts.label("hosts"),
                    func.sum(case((NetworkEvent.anomalous.is_(True), 1), else_=0))
                    .label("flagged"),
                )
                .where(NetworkEvent.timestamp >= start,
                       NetworkEvent.timestamp < stop)
                .group_by(NetworkEvent.src_ip)
                .having(or_(
                    distinct_ports >= min_ports,
                    distinct_hosts >= min_destinations,
                    count >= burst_per_minute * WINDOW_MINUTES,
                ))
                .order_by(NetworkEvent.src_ip.asc())
                .limit(PAGE_SIZE)
            )
            if cursor is not None:
                query = query.where(NetworkEvent.src_ip > cursor)
            rows = session.execute(query).mappings().all()
            if not rows:
                break
            if candidates + len(rows) > max_candidates:
                # Never silently truncate an incident stream. Already committed
                # windows are safe to replay because the PK is deterministic.
                session.rollback()
                raise RuntimeError("Behavior candidate cap exceeded; resize worker/backfill")
            observed = now_utc()
            payload = []
            for r in rows:
                ports, hosts, flows, flagged = (
                    int(r["ports"]), int(r["hosts"]), int(r["flow_count"]), int(r["flagged"])
                )
                patterns = []
                if ports >= min_ports:
                    patterns.append("port_sweep_like")
                if hosts >= min_destinations:
                    patterns.append("destination_fanout_like")
                if flows >= burst_per_minute * WINDOW_MINUTES:
                    patterns.append("connection_burst_like")
                payload.append({
                    "id": finding_id(r["source_ip"], start),
                    "source_ip": r["source_ip"], "window_start": start,
                    "window_minutes": WINDOW_MINUTES,
                    "patterns": patterns, "flow_count": flows,
                    "destination_ports": ports, "destination_hosts": hosts,
                    "flagged_flows": flagged,
                    "severity": _severity(patterns, flagged),
                    "status": "open", "assigned_to": None,
                    "created_at": observed, "updated_at": observed,
                })
            statement = insert_fn(BehaviorFinding).values(payload)
            excluded = statement.excluded
            grown = excluded.flow_count > BehaviorFinding.flow_count
            statement = statement.on_conflict_do_update(
                index_elements=[BehaviorFinding.id],
                set_={
                    # Late events can increase evidence; existing human review
                    # status, ownership and creation time must remain intact.
                    field: case((grown, getattr(excluded, field)),
                                else_=getattr(BehaviorFinding, field))
                    for field in (
                        "patterns", "flow_count", "destination_ports",
                        "destination_hosts", "flagged_flows", "severity", "updated_at"
                    )
                },
            )
            session.execute(statement)
            session.commit()
            candidates += len(rows)
            cursor = rows[-1]["source_ip"]
            if len(rows) < PAGE_SIZE:
                break
        completed += 1
    return {
        "window_minutes": WINDOW_MINUTES,
        "windows_scanned": completed,
        "candidate_upserts": candidates,
        "cutoff_utc": boundary.isoformat(),
        "lookback_minutes": lookback_minutes,
        "lateness_minutes": lateness_minutes,
        "disclaimer": "Heuristic behavior cases, not verified intrusions; zero candidates is valid.",
    }
