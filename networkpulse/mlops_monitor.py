"""Production MLOps evidence for the exact deployed model and committed flows.

This is the application runtime pipeline (HTTP/Redis ingestion -> SQL events
-> pinned Detector -> durable aggregate report), not a test-only benchmark.
Unlabeled production data cannot establish predictive accuracy.
"""
from __future__ import annotations

import hashlib
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from networkpulse.detector import Detector
from networkpulse.drift import drift_report
from networkpulse.model_registry import sha256
from networkpulse.schemas import FlowEvent
from networkpulse.storage import MLOpsDriftRun, NetworkEvent, now_utc


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("monitor windows require timezone-aware UTC bounds")
    return value.astimezone(timezone.utc)


def run_monitor(
    session: Session, *, model_path: Path, expected_sha256: str,
    start: datetime, end: datetime, max_rows: int = 5000,
    psi_warning: float = .2, psi_critical: float = .4,
    max_alert_fraction: float = .15,
) -> dict:
    """Persist an immutable report over ALL committed flows in a bounded range.

    Identity includes artifact hash, UTC bounds and SHA-256 of ordered unique
    flow IDs; reruns with identical inputs are idempotent. Late arrivals create
    a *new* immutable snapshot rather than silently changing older evidence.
    """
    begin, finish = _utc(start), _utc(end)
    if not timedelta(minutes=5) <= finish - begin <= timedelta(days=7):
        raise ValueError("monitor interval must be between 5 minutes and 7 days")
    if not 30 <= max_rows <= 10000:
        raise ValueError("max_rows must be 30..10000")
    if not expected_sha256 or len(expected_sha256) != 64:
        raise ValueError("trusted model SHA-256 pin is required")
    actual_sha = sha256(Path(model_path))
    if actual_sha != expected_sha256:
        raise ValueError("trusted model artifact checksum mismatch")
    if not 0 < psi_warning < psi_critical or not 0 < max_alert_fraction <= 1:
        raise ValueError("invalid monitoring threshold")
    # Exact source records for the selected window. This limit is an explicit
    # FAILURE GATE, NOT hidden sampling or silent top-N evaluation.
    rows = session.scalars(
        select(NetworkEvent).where(
            NetworkEvent.timestamp >= begin, NetworkEvent.timestamp < finish,
        ).order_by(NetworkEvent.timestamp.asc(), NetworkEvent.id.asc())
        .limit(max_rows + 1)
    ).all()
    if len(rows) > max_rows:
        raise RuntimeError("monitor window exceeds max_rows; split windows or provision rollups")
    if len(rows) < 30:
        return {
            "created": False, "status": "insufficient_data",
            "flow_count": len(rows), "model_sha256": actual_sha,
            "window_start_utc": begin.isoformat(),
            "window_end_utc": finish.isoformat(),
            "warning": "Below 30 flows; PSI not computed; not a healthy/drift-free signal.",
        }
    digest = hashlib.sha256()
    sources = Counter()
    events = []
    for row in rows:
        # SQL backends vary in timezone return handling. The ingested contract
        # stores UTC timestamps; SQLite usually materializes naive UTC.
        timestamp = row.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        digest.update(row.id.encode("ascii"))
        digest.update(b"\n")
        sources[row.source] += 1
        events.append(FlowEvent.model_validate({
            "timestamp": timestamp,
            "source": row.source, "uid": row.uid,
            "src_ip": row.src_ip, "dst_ip": row.dst_ip,
            "src_port": row.src_port, "dst_port": row.dst_port,
            "proto": row.proto, "duration": row.duration,
            "orig_bytes": row.orig_bytes, "resp_bytes": row.resp_bytes,
            "orig_pkts": row.orig_pkts, "resp_pkts": row.resp_pkts,
            "conn_state": row.conn_state,
            # Historical labels are NOT recovered/inferred from predictions.
            "label": None,
        }))
    fingerprint = digest.hexdigest()
    key = hashlib.sha256((
        "mlops-v1|" + actual_sha + "|" + begin.isoformat() + "|" +
        finish.isoformat() + "|" + fingerprint
    ).encode()).hexdigest()[:32]
    # Avoid expensive refitting; exact deployed artifact is loaded *after*
    # checking its checksum. joblib must be a trusted local file.
    existing = session.get(MLOpsDriftRun, key)
    if existing is not None:
        return {
            "id": key, "created": False,
            "model_sha256": actual_sha, "input_fingerprint": fingerprint,
            "flow_count": existing.flow_count, "drift_status": existing.drift_status,
            "alert_budget_exceeded": existing.alert_budget_exceeded,
        }
    detector = Detector.load(Path(model_path))
    report = drift_report(
        detector, events, psi_warning=psi_warning,
        psi_critical=psi_critical, max_alert_fraction=max_alert_fraction,
    )
    # Immutable aggregate evidence only: no original source/destination IPs,
    # timestamps of individual sessions, packet payloads, labels or secrets.
    report["data_lineage"] = {
        "source_contract": "network_events_v1",
        "feature_version": detector.metadata.get("feature_version"),
        "input_fingerprint_sha256": fingerprint,
        "source_counts": dict(sorted(sources.items())),
        "window_start_utc": begin.isoformat(),
        "window_end_utc": finish.isoformat(),
        "exact_committed_rows": len(rows),
        "model_artifact_sha256": actual_sha,
        "labels_available": False,
        "complete_window_no_sampling": True,
    }
    payload = {
        "id": key, "model_sha256": actual_sha,
        "window_start": begin, "window_end": finish,
        "input_fingerprint": fingerprint, "flow_count": len(rows),
        "flagged_flows": report["alerts"],
        "drift_status": report["drift_status"],
        "alert_budget_exceeded": report["alert_budget_exceeded"],
        "worst_psi": report["worst_psi"],
        "report": report, "created_at": now_utc(),
    }
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        insert_fn = pg_insert
    elif dialect == "sqlite":
        insert_fn = sqlite_insert
    else:
        raise ValueError("MLOps monitoring supports PostgreSQL/SQLite only")
    statement = insert_fn(MLOpsDriftRun).values(payload).on_conflict_do_nothing(
        index_elements=[MLOpsDriftRun.id]
    ).returning(MLOpsDriftRun.id)
    try:
        inserted = session.scalar(statement) is not None
        session.commit()
    except Exception:
        session.rollback()
        raise
    return {
        "id": key, "created": inserted,
        "model_sha256": actual_sha, "input_fingerprint": fingerprint,
        "flow_count": len(rows),
        "drift_status": report["drift_status"],
        "alert_budget_exceeded": report["alert_budget_exceeded"],
        "worst_psi": report["worst_psi"],
        "interpretation": "Unlabeled flow drift and alert budget only; no accuracy claim.",
    }


def completed_hour(*, now: datetime | None = None, delay_minutes: int = 10) -> tuple[datetime, datetime]:
    """Most recent fully closed UTC hour after a configurable arrival grace period."""
    if not 0 <= delay_minutes <= 120:
        raise ValueError("delay_minutes must be 0..120")
    instant = _utc(now or datetime.now(timezone.utc)) - timedelta(minutes=delay_minutes)
    finish = instant.replace(minute=0, second=0, microsecond=0)
    return finish - timedelta(hours=1), finish
