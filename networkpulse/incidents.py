"""Bounded, replay-safe multi-window SOC incident correlation.

A source/hour episode aggregates two or more persisted, completed 5-minute
behavior windows. Stable UTC-hour identities avoid historical re-parenting,
cross-worker races, and surprising case reassignment. Incidents are heuristic
investigation candidates only; not attack attribution or network blocking.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import case, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from networkpulse.storage import BehaviorFinding, BehaviorIncident, now_utc

PAGE_SIZE = 100


def _utc(dt: datetime) -> datetime:
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("Correlation cutoff requires timezone-aware UTC time")
    return dt.astimezone(timezone.utc)


def _db_utc(value: datetime) -> datetime:
    # SQLite loads UTC DateTime(timezone=True) values without tzinfo.
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else _utc(value)


def incident_id(source_ip: str, hour: datetime) -> str:
    timestamp = _utc(hour)
    if timestamp.minute or timestamp.second or timestamp.microsecond:
        raise ValueError("Incident start must be UTC hour aligned")
    return hashlib.sha256(
        f"incident-v1|{source_ip}|{timestamp.isoformat()}".encode()
    ).hexdigest()[:32]


def _severity(count: int, flagged: int, signals: list[str]) -> str:
    # Triage prioritization, never a calibrated probability of intrusion.
    if (count >= 3 and flagged > 0) or (count >= 4 and len(signals) >= 2):
        return "high"
    return "medium"


def materialize_incidents(
    session: Session, *, until: datetime | None = None,
    lookback_hours: int = 3, lateness_minutes: int = 2,
    max_sources: int = 10000,
) -> dict:
    """Create/update one evidence-backed source/hour episode per UTC hour.

    Only completed five-minute windows are considered, and each incident
    needs at least two distinct source windows. Processing multiple hourly
    buckets and historical replays is deterministic. Evidence never resets
    analyst dispositions or ownership. A cap fails visibly, not by sampling.
    """
    if not 1 <= lookback_hours <= 24:
        raise ValueError("lookback_hours must be 1..24")
    if not 0 <= lateness_minutes <= 60:
        raise ValueError("lateness_minutes must be 0..60")
    if not 100 <= max_sources <= 100000:
        raise ValueError("max_sources must be 100..100000")
    now = _utc(until or datetime.now(timezone.utc))
    watermark = now - timedelta(minutes=lateness_minutes)
    complete_end = datetime.fromtimestamp(
        (int(watermark.timestamp()) // 300) * 300, tz=timezone.utc,
    )
    latest_hour = complete_end.replace(minute=0, second=0, microsecond=0)
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        insert_fn = pg_insert
    elif dialect == "sqlite":
        insert_fn = sqlite_insert
    else:
        raise ValueError("Incident correlation supports PostgreSQL/SQLite only")

    candidate_sources = 0
    upserts = 0
    for offset in reversed(range(lookback_hours)):
        start = latest_hour - timedelta(hours=offset)
        stop = min(start + timedelta(hours=1), complete_end)
        if stop <= start:
            continue
        cursor = None
        while True:
            grouped = (
                select(BehaviorFinding.source_ip)
                .where(BehaviorFinding.window_start >= start,
                       BehaviorFinding.window_start < stop)
                .group_by(BehaviorFinding.source_ip)
                .having(func.count(BehaviorFinding.id) >= 2)
                .order_by(BehaviorFinding.source_ip.asc())
                .limit(PAGE_SIZE)
            )
            if cursor is not None:
                grouped = grouped.where(BehaviorFinding.source_ip > cursor)
            sources = list(session.scalars(grouped))
            if not sources:
                break
            if candidate_sources + len(sources) > max_sources:
                session.rollback()
                raise RuntimeError("Incident candidate source cap exceeded; backfill smaller periods")
            payload = []
            timestamp = now_utc()
            for source in sources:
                findings = list(session.scalars(
                    select(BehaviorFinding).where(
                        BehaviorFinding.source_ip == source,
                        BehaviorFinding.window_start >= start,
                        BehaviorFinding.window_start < stop,
                    ).order_by(
                        BehaviorFinding.window_start.asc(), BehaviorFinding.id.asc(),
                    )
                ))
                # Bounded by twelve five-minute windows per source/hour.
                if len(findings) < 2:
                    continue
                members = [f.id for f in findings]
                patterns = sorted({s for f in findings for s in f.patterns})
                total_flows = sum(f.flow_count for f in findings)
                flagged = sum(f.flagged_flows for f in findings)
                payload.append({
                    "id": incident_id(source, start),
                    "source_ip": source,
                    "hour_start": start, "window_count": len(members),
                    "finding_ids": members, "patterns": patterns,
                    "first_seen": _db_utc(findings[0].window_start),
                    "last_seen": _db_utc(findings[-1].window_start),
                    "total_flows": total_flows, "flagged_flows": flagged,
                    "severity": _severity(len(members), flagged, patterns),
                    "status": "open", "assigned_to": None,
                    "created_at": timestamp, "updated_at": timestamp,
                })
            if payload:
                statement = insert_fn(BehaviorIncident).values(payload)
                excluded = statement.excluded
                grown = or_(
                    excluded.window_count > BehaviorIncident.window_count,
                    excluded.total_flows > BehaviorIncident.total_flows,
                    excluded.flagged_flows > BehaviorIncident.flagged_flows,
                )
                statement = statement.on_conflict_do_update(
                    index_elements=[BehaviorIncident.id],
                    set_={
                        name: case((grown, getattr(excluded, name)),
                                   else_=getattr(BehaviorIncident, name))
                        for name in (
                            "window_count", "finding_ids", "patterns",
                            "first_seen", "last_seen", "total_flows",
                            "flagged_flows", "severity", "updated_at",
                        )
                    },
                )
                session.execute(statement)
                session.commit()
                upserts += len(payload)
            candidate_sources += len(sources)
            cursor = sources[-1]
            if len(sources) < PAGE_SIZE:
                break
    return {
        "candidate_upserts": upserts,
        "source_hours_scanned": lookback_hours,
        "candidate_source_hours": candidate_sources,
        "completed_before_utc": complete_end.isoformat(),
        "disclaimer": "Hourly source correlation heuristic; not confirmed intrusion or attack attribution.",
    }
