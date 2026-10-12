"""Orchestration layer between a trusted model, validated input and storage."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from networkpulse.detector import Detector
from networkpulse.schemas import FlowEvent
from networkpulse.storage import Alert, AlertAudit, NetworkEvent


def severity(risk: int) -> str:
    if risk >= 90:
        return "critical"
    if risk >= 76:
        return "high"
    if risk >= 60:
        return "medium"
    return "low"


def ingest(session: Session, model: Detector, events: list[FlowEvent]) -> dict:
    """Atomic, concurrent-safe flow upsert and alert creation in one transaction.

    A prior SELECT is intentionally avoided: concurrent writers can pass such a
    check simultaneously. The database uniqueness constraint arbitrates inserts.
    Both event and alert changes commit together, or both roll back.
    """
    if not events:
        return {"received": 0, "inserted": 0, "duplicates": 0, "alerts_created": 0}
    unique = {event.key(): event for event in events}
    detections = model.score(list(unique.values()))
    payload = []
    alerts = []
    for (key, event), result in zip(unique.items(), detections):
        payload.append({
            "id": key, "timestamp": event.timestamp, "source": event.source,
            "uid": event.uid, "src_ip": str(event.src_ip), "dst_ip": str(event.dst_ip),
            "src_port": event.src_port, "dst_port": event.dst_port,
            "proto": event.proto, "duration": event.duration,
            "orig_bytes": event.orig_bytes, "resp_bytes": event.resp_bytes,
            "orig_pkts": event.orig_pkts, "resp_pkts": event.resp_pkts,
            "conn_state": event.conn_state, "anomaly_score": result.anomaly_score,
            "risk": result.risk, "anomalous": result.anomalous,
        })
        if result.anomalous:
            alerts.append({"event_id": key, "severity": severity(result.risk),
                           "reasons": result.reasons, "status": "open"})

    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        insert_fn = pg_insert
    elif dialect == "sqlite":
        insert_fn = sqlite_insert
    else:
        raise ValueError("Atomic ingestion supports PostgreSQL and SQLite only")

    inserted: set[str] = set()
    # Keep SQL parameter counts below SQLite's older 999-variable limit.
    # 25 rows x 18-20 columns is safely below that ceiling.
    with session.begin():
        for offset in range(0, len(payload), 25):
            chunk = payload[offset: offset + 25]
            stmt = (insert_fn(NetworkEvent).values(chunk)
                    .on_conflict_do_nothing(index_elements=[NetworkEvent.id])
                    .returning(NetworkEvent.id))
            inserted.update(session.scalars(stmt).all())
        chosen_alerts = [a for a in alerts if a["event_id"] in inserted]
        for offset in range(0, len(chosen_alerts), 25):
            chunk = chosen_alerts[offset: offset + 25]
            stmt = (insert_fn(Alert).values(chunk)
                    .on_conflict_do_nothing(index_elements=[Alert.event_id]))
            session.execute(stmt)

    return {
        "received": len(events), "inserted": len(inserted),
        "duplicates": len(events) - len(inserted),
        "alerts_created": len(chosen_alerts),
    }


def change_alert(session: Session, alert: Alert, new_status: str, note: str,
                 actor: str = "local-operator") -> None:
    old = alert.status
    alert.status = new_status
    alert.updated_at = datetime.now(timezone.utc)
    session.add(AlertAudit(
        alert_id=alert.id, old_status=old, new_status=new_status, note=note,
        actor=actor[:150]
    ))
    session.commit()
