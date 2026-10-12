"""NetworkPulse API. Read-only dashboard endpoints; authenticated mutation endpoints."""

from __future__ import annotations

import secrets
import csv
import io
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from networkpulse.config import Settings
from networkpulse.security.oidc import Principal, TokenVerifier
from networkpulse.security.limits import security_middleware_factory
from networkpulse.observability import metric_middleware, exporter, INGEST_TOTAL, ALERT_ACTIONS, MODEL_INFERENCE
import time
from networkpulse.detector import Detector
from networkpulse.schemas import AlertPatch, AlertAssignment, AnalystNote, FlowBatch
from networkpulse.service import change_alert, ingest
from networkpulse.storage import Alert, AlertAudit, AlertNote, NetworkEvent, build_sessions, counts

STATIC = Path(__file__).parent / "static"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    make_session = build_sessions(settings.database_url)
    # Persist models trained offline; do not auto-train on incoming production data.
    if settings.model_sha256 and settings.model_path.is_file():
        from networkpulse.model_registry import sha256
        if len(settings.model_sha256) != 64 or sha256(settings.model_path) != settings.model_sha256:
            raise ValueError('Trusted model artifact SHA-256 verification failed')
    model = Detector.load(settings.model_path) if settings.model_path.is_file() else None
    verifier = (TokenVerifier(settings.oidc_issuer, settings.oidc_audience,
                              settings.oidc_jwks_url, settings.oidc_role_claim)
                if settings.auth_mode == "oidc" else None)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        try:
            yield
        finally:
            make_session.kw["bind"].dispose()

    app = FastAPI(
        lifespan=lifespan,
        title="NetworkPulse AI", version="0.5.0",
        description="Flow observability, anomaly triage and auditable review. Not an IDS replacement.",
    )

    app.middleware("http")(metric_middleware)
    app.middleware("http")(security_middleware_factory(
        max_body_bytes=settings.max_body_bytes, per_minute=settings.mutation_rate_per_minute))

    def require_identity(authorization: Annotated[str | None, Header()] = None) -> Principal:
        if verifier is None:
            return Principal(subject="local-operator", role="admin")
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, detail="OIDC bearer access token required")
        return verifier.verify(authorization[len("Bearer "):])

    def read_scope(principal: Principal = Depends(require_identity)) -> Principal:
        principal.require("viewer")
        return principal

    def analyst_scope(principal: Principal = Depends(require_identity)) -> Principal:
        principal.require("analyst")
        return principal

    def get_db():
        with make_session() as session:
            yield session

    def require_api_key(x_api_key: Annotated[str | None, Header()] = None,
                        principal: Principal = Depends(require_identity)):
        if verifier is not None:
            principal.require("analyst")
        elif not x_api_key or not secrets.compare_digest(x_api_key, settings.api_key):
            raise HTTPException(status_code=401, detail="Valid X-API-Key required")

    def require_model() -> Detector:
        if model is None:
            raise HTTPException(status_code=503, detail="Model not trained; run networkpulse bootstrap")
        return model

    @app.get("/", include_in_schema=False, dependencies=[Depends(read_scope)])
    def dashboard():
        return FileResponse(STATIC / "index.html")

    @app.get("/static/{filename}", include_in_schema=False)
    def static_file(filename: str):
        if filename not in {"app.js", "styles.css"}:
            raise HTTPException(404, detail="Not found")
        return FileResponse(STATIC / filename)

    @app.get("/metrics", include_in_schema=False)
    def metrics(principal: Principal = Depends(read_scope)):
        principal.require("admin")
        return exporter()

    @app.get("/health/live", tags=["operations"])
    def liveness():
        return {"status": "ok"}

    @app.get("/health/ready", tags=["operations"])
    def readiness():
        if model is None:
            raise HTTPException(503, detail="Model artifact unavailable")
        with make_session() as session:
            counts(session)
        return {"status": "ready", "model_source": model.metadata.get("source")}

    @app.get("/api/v1/intelligence/hosts", tags=["analytics"], dependencies=[Depends(read_scope)])
    def intelligence_hosts(
        limit_flows: int = Query(20000, ge=1, le=100000),
        limit_hosts: int = Query(50, ge=1, le=200),
        db: Session = Depends(get_db),
    ):
        from networkpulse.intelligence import host_behavior
        return host_behavior(db, limit_flows=limit_flows, max_hosts=limit_hosts)

    @app.get("/api/v1/intelligence/correlations", tags=["analytics"],
             dependencies=[Depends(read_scope)])
    def correlation_windows(window_minutes: int = Query(10, ge=1, le=120),
                            min_ports: int = Query(4, ge=2, le=1000),
                            min_destinations: int = Query(4, ge=2, le=1000),
                            db: Session = Depends(get_db)):
        from networkpulse.intelligence import correlate_windows
        return {"correlations": correlate_windows(db, window_minutes=window_minutes,
                min_ports=min_ports, min_destinations=min_destinations),
                "disclaimer": "Heuristic flow correlation, not confirmed attacks."}

    @app.get("/api/v1/model", tags=["model"], dependencies=[Depends(read_scope)])
    def model_info():
        detector = require_model()
        # Training metadata is descriptive, not an independent certification.
        return detector.metadata | {"threshold": detector.threshold, "feature_contract": "v1"}

    @app.post("/api/v1/ingest", dependencies=[Depends(require_api_key)], tags=["flows"])
    def ingest_batch(batch: FlowBatch, db: Session = Depends(get_db)):
        if len(batch.events) > settings.max_batch:
            raise HTTPException(413, detail="Batch exceeds MAX_BATCH")
        started = time.perf_counter()
        result = ingest(db, require_model(), batch.events)
        MODEL_INFERENCE.observe(time.perf_counter() - started)
        for key in ("inserted", "duplicates"):
            INGEST_TOTAL.labels(key).inc(result[key])
        return result

    @app.get("/api/v1/summary", tags=["analytics"], dependencies=[Depends(read_scope)])
    def summary(db: Session = Depends(get_db)):
        return counts(db)

    @app.get("/api/v1/events", tags=["flows"], dependencies=[Depends(read_scope)])
    def list_events(
        limit: int = Query(25, ge=1, le=100),
        offset: int = Query(0, ge=0),
        anomalies_only: bool = False,
        src_ip: str | None = None,
        db: Session = Depends(get_db),
    ):
        query = select(NetworkEvent)
        if anomalies_only:
            query = query.where(NetworkEvent.anomalous.is_(True))
        if src_ip:
            query = query.where(NetworkEvent.src_ip == src_ip)
        events = db.scalars(query.order_by(NetworkEvent.timestamp.desc()).offset(offset).limit(limit)).all()
        return [{
            "id": e.id, "timestamp": e.timestamp, "source": e.source,
            "src_ip": e.src_ip, "dst_ip": e.dst_ip, "dst_port": e.dst_port,
            "proto": e.proto, "orig_bytes": e.orig_bytes, "resp_bytes": e.resp_bytes,
            "risk": e.risk, "anomalous": e.anomalous,
        } for e in events]

    @app.get("/api/v1/alerts", tags=["alerts"], dependencies=[Depends(read_scope)])
    def list_alerts(
        limit: int = Query(30, ge=1, le=100),
        status: str | None = Query(default=None, pattern="^(open|investigating|resolved|false_positive)$"),
        severity: Literal["low", "medium", "high", "critical"] | None = None,
        src_ip: str | None = Query(default=None, max_length=45),
        protocol: Literal["tcp", "udp", "icmp", "other"] | None = None,
        min_risk: int = Query(0, ge=0, le=100),
        offset: int = Query(0, ge=0),
        order: Literal["newest", "oldest", "highest_risk"] = "newest",
        db: Session = Depends(get_db),
    ):
        stmt = select(Alert, NetworkEvent).join(NetworkEvent, Alert.event_id == NetworkEvent.id)
        if status:
            stmt = stmt.where(Alert.status == status)
        if severity:
            stmt = stmt.where(Alert.severity == severity)
        if src_ip:
            stmt = stmt.where(NetworkEvent.src_ip == src_ip)
        if protocol:
            stmt = stmt.where(NetworkEvent.proto == protocol)
        stmt = stmt.where(NetworkEvent.risk >= min_risk)
        sort = (NetworkEvent.risk.desc() if order == "highest_risk"
                else NetworkEvent.timestamp.asc() if order == "oldest"
                else NetworkEvent.timestamp.desc())
        pairs = db.execute(stmt.order_by(sort, Alert.id.desc()).offset(offset).limit(limit)).all()
        return [{
            "id": a.id, "severity": a.severity, "status": a.status,
            "created_at": a.created_at, "reasons": a.reasons,
            "assigned_to": a.assigned_to,
            "src_ip": e.src_ip, "dst_ip": e.dst_ip, "dst_port": e.dst_port,
            "timestamp": e.timestamp, "risk": e.risk, "event_id": e.id,
        } for a, e in pairs]

    @app.patch("/api/v1/alerts/{alert_id}", dependencies=[Depends(require_api_key)], tags=["alerts"])
    def update_alert(alert_id: int, patch: AlertPatch, db: Session = Depends(get_db),
                     principal: Principal = Depends(require_identity)):
        obj = db.get(Alert, alert_id)
        if obj is None:
            raise HTTPException(404, detail="Alert not found")
        change_alert(db, obj, patch.status, patch.note, actor=principal.subject)
        ALERT_ACTIONS.labels(patch.status).inc()
        return {"id": obj.id, "status": obj.status, "updated_at": obj.updated_at}

    @app.get("/api/v1/alerts/{alert_id}/history", tags=["alerts"], dependencies=[Depends(read_scope)])
    def alert_history(alert_id: int, db: Session = Depends(get_db)):
        if db.get(Alert, alert_id) is None:
            raise HTTPException(404, detail="Alert not found")
        rows = db.scalars(select(AlertAudit).where(AlertAudit.alert_id == alert_id)
                         .order_by(AlertAudit.changed_at.desc())).all()
        return [{"old_status": x.old_status, "new_status": x.new_status,
                 "note": x.note, "changed_at": x.changed_at, "actor": x.actor} for x in rows]

    @app.get("/api/v1/alerts/{alert_id}/detail", tags=["alerts"],
             dependencies=[Depends(read_scope)])
    def alert_detail(alert_id: int, db: Session = Depends(get_db)):
        alert = db.get(Alert, alert_id)
        if alert is None:
            raise HTTPException(404, detail="Alert not found")
        flow = db.get(NetworkEvent, alert.event_id)
        notes = db.scalars(select(AlertNote).where(AlertNote.alert_id == alert_id)
                           .order_by(AlertNote.created_at.desc()).limit(100)).all()
        return {
            "id": alert.id, "status": alert.status, "severity": alert.severity,
            "assigned_to": alert.assigned_to, "reasons": alert.reasons,
            "risk": flow.risk, "anomaly_score": flow.anomaly_score,
            "event": {column.name: getattr(flow, column.name)
                      for column in NetworkEvent.__table__.columns},
            "notes": [{"actor": n.actor, "note": n.note,
                       "created_at": n.created_at} for n in notes],
        }

    @app.post("/api/v1/alerts/{alert_id}/notes", tags=["alerts"],
              dependencies=[Depends(require_api_key)])
    def add_alert_note(alert_id: int, payload: AnalystNote,
                       principal: Principal = Depends(analyst_scope),
                       db: Session = Depends(get_db)):
        if db.get(Alert, alert_id) is None:
            raise HTTPException(404, detail="Alert not found")
        note = AlertNote(alert_id=alert_id, actor=principal.subject, note=payload.note)
        db.add(note)
        db.commit()
        return {"id": note.id, "actor": principal.subject}

    @app.patch("/api/v1/alerts/{alert_id}/assignment", tags=["alerts"],
               dependencies=[Depends(require_api_key)])
    def assign_alert(alert_id: int, payload: AlertAssignment,
                     principal: Principal = Depends(analyst_scope),
                     db: Session = Depends(get_db)):
        alert = db.get(Alert, alert_id)
        if alert is None:
            raise HTTPException(404, detail="Alert not found")
        old = alert.assigned_to
        alert.assigned_to = payload.assigned_to
        db.add(AlertNote(alert_id=alert_id, actor=principal.subject,
                         note=f"Ownership: {old or 'unassigned'} -> {payload.assigned_to or 'unassigned'}; {payload.note}"))
        db.commit()
        return {"id": alert_id, "assigned_to": alert.assigned_to}

    @app.get("/api/v1/alerts/export.csv", tags=["alerts"],
             dependencies=[Depends(read_scope)])
    def export_alerts(db: Session = Depends(get_db),
                      limit: int = Query(1000, ge=1, le=5000)):
        data = db.execute(select(Alert, NetworkEvent).join(NetworkEvent)
                          .order_by(Alert.created_at.desc()).limit(limit)).all()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['alert_id', 'severity', 'status', 'assigned_to', 'src_ip',
                         'dst_ip', 'dst_port', 'risk', 'created_at'])
        for alert, flow in data:
            record = [alert.id, alert.severity, alert.status, alert.assigned_to or '',
                      flow.src_ip, flow.dst_ip, flow.dst_port, flow.risk,
                      alert.created_at.isoformat()]
            writer.writerow(["'" + x if isinstance(x, str) and x.startswith(('=', '+', '-', '@'))
                             else x for x in record])
        return Response(content=output.getvalue(), media_type='text/csv',
                        headers={'Content-Disposition': 'attachment; filename=networkpulse-alerts.csv'})

    @app.get("/api/v1/trends", tags=["analytics"], dependencies=[Depends(read_scope)])
    def trends(limit: int = Query(5000, ge=1, le=10000), db: Session = Depends(get_db)):
        """Five-minute UTC buckets derived from stored event timestamps."""
        rows = db.scalars(select(NetworkEvent).order_by(NetworkEvent.timestamp.desc()).limit(limit)).all()
        buckets: dict[str, dict[str, int]] = {}
        for event in rows:
            bucket = event.timestamp.strftime("%Y-%m-%d %H:") + f"{(event.timestamp.minute // 5) * 5:02d} UTC"
            v = buckets.setdefault(bucket, {"flows": 0, "anomalies": 0})
            v["flows"] += 1
            v["anomalies"] += int(event.anomalous)
        return [{"time": k, **v} for k, v in sorted(buckets.items())]

    return app


# For `uvicorn networkpulse.api:app`, environment configuration is required.
# `networkpulse bootstrap` should be run before starting the service.
app = None  # Use the --factory form: `uvicorn networkpulse.api:create_app --factory`.
