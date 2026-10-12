"""Orchestration layer between a trusted model, validated input and storage."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
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
    """Idempotent insert. A duplicate does not create a second event or alert."""
    if not events:
        return {"received": 0, "inserted": 0, "duplicates": 0, "alerts_created": 0}
    unique = dict((event.key(), event) for event in events)
    existing = set(session.scalars(select(NetworkEvent.id).where(NetworkEvent.id.in_(unique))).all())
    unseen = [(key, event) for key, event in unique.items() if key not in existing]
    detections = model.score([event for _, event in unseen])
    alert_count = 0
    for (key, event), result in zip(unseen, detections):
        session.add(NetworkEvent(
            id=key, timestamp=event.timestamp, source=event.source,
            uid=event.uid, src_ip=str(event.src_ip), dst_ip=str(event.dst_ip),
            src_port=event.src_port, dst_port=event.dst_port,
            proto=event.proto, duration=event.duration,
            orig_bytes=event.orig_bytes, resp_bytes=event.resp_bytes,
            orig_pkts=event.orig_pkts, resp_pkts=event.resp_pkts,
            conn_state=event.conn_state,
            anomaly_score=result.anomaly_score, risk=result.risk, anomalous=result.anomalous,
        ))
        if result.anomalous:
            session.add(Alert(event_id=key, severity=severity(result.risk), reasons=result.reasons))
            alert_count += 1
    session.commit()
    return {
        "received": len(events), "inserted": len(unseen),
        "duplicates": len(events) - len(unseen), "alerts_created": alert_count,
    }


def change_alert(session: Session, alert: Alert, new_status: str, note: str) -> None:
    old = alert.status
    alert.status = new_status
    alert.updated_at = datetime.now(timezone.utc)
    session.add(AlertAudit(
        alert_id=alert.id, old_status=old, new_status=new_status, note=note
    ))
    session.commit()
