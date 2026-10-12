"""NetworkPulse API. Read-only dashboard endpoints; authenticated mutation endpoints."""

from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from networkpulse.config import Settings
from networkpulse.detector import Detector
from networkpulse.schemas import AlertPatch, FlowBatch
from networkpulse.service import change_alert, ingest
from networkpulse.storage import Alert, AlertAudit, NetworkEvent, build_sessions, counts

STATIC = Path(__file__).parent / "static"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    make_session = build_sessions(settings.database_url)
    # Persist models trained offline; do not auto-train on incoming production data.
    model = Detector.load(settings.model_path) if settings.model_path.is_file() else None

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        try:
            yield
        finally:
            make_session.kw["bind"].dispose()

    app = FastAPI(
        lifespan=lifespan,
        title="NetworkPulse AI", version="0.2.0",
        description="Flow observability, anomaly triage and auditable review. Not an IDS replacement.",
    )

    def get_db():
        with make_session() as session:
            yield session

    def require_api_key(x_api_key: Annotated[str | None, Header()] = None):
        if not x_api_key or not secrets.compare_digest(x_api_key, settings.api_key):
            raise HTTPException(status_code=401, detail="Valid X-API-Key required")

    def require_model() -> Detector:
        if model is None:
            raise HTTPException(status_code=503, detail="Model not trained; run networkpulse bootstrap")
        return model

    @app.get("/", include_in_schema=False)
    def dashboard():
        return FileResponse(STATIC / "index.html")

    @app.get("/static/{filename}", include_in_schema=False)
    def static_file(filename: str):
        if filename not in {"app.js", "styles.css"}:
            raise HTTPException(404, detail="Not found")
        return FileResponse(STATIC / filename)

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

    @app.get("/api/v1/model", tags=["model"])
    def model_info():
        detector = require_model()
        # Training metadata is descriptive, not an independent certification.
        return detector.metadata | {"threshold": detector.threshold, "feature_contract": "v1"}

    @app.post("/api/v1/ingest", dependencies=[Depends(require_api_key)], tags=["flows"])
    def ingest_batch(batch: FlowBatch, db: Session = Depends(get_db)):
        if len(batch.events) > settings.max_batch:
            raise HTTPException(413, detail="Batch exceeds MAX_BATCH")
        return ingest(db, require_model(), batch.events)

    @app.get("/api/v1/summary", tags=["analytics"])
    def summary(db: Session = Depends(get_db)):
        return counts(db)

    @app.get("/api/v1/events", tags=["flows"])
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

    @app.get("/api/v1/alerts", tags=["alerts"])
    def list_alerts(
        limit: int = Query(30, ge=1, le=100),
        status: str | None = Query(default=None, pattern="^(open|investigating|resolved|false_positive)$"),
        db: Session = Depends(get_db),
    ):
        stmt = select(Alert, NetworkEvent).join(NetworkEvent, Alert.event_id == NetworkEvent.id)
        if status:
            stmt = stmt.where(Alert.status == status)
        pairs = db.execute(stmt.order_by(Alert.created_at.desc()).limit(limit)).all()
        return [{
            "id": a.id, "severity": a.severity, "status": a.status,
            "created_at": a.created_at, "reasons": a.reasons,
            "src_ip": e.src_ip, "dst_ip": e.dst_ip, "dst_port": e.dst_port,
            "timestamp": e.timestamp, "risk": e.risk, "event_id": e.id,
        } for a, e in pairs]

    @app.patch("/api/v1/alerts/{alert_id}", dependencies=[Depends(require_api_key)], tags=["alerts"])
    def update_alert(alert_id: int, patch: AlertPatch, db: Session = Depends(get_db)):
        obj = db.get(Alert, alert_id)
        if obj is None:
            raise HTTPException(404, detail="Alert not found")
        change_alert(db, obj, patch.status, patch.note)
        return {"id": obj.id, "status": obj.status, "updated_at": obj.updated_at}

    @app.get("/api/v1/alerts/{alert_id}/history", tags=["alerts"])
    def alert_history(alert_id: int, db: Session = Depends(get_db)):
        if db.get(Alert, alert_id) is None:
            raise HTTPException(404, detail="Alert not found")
        rows = db.scalars(select(AlertAudit).where(AlertAudit.alert_id == alert_id)
                         .order_by(AlertAudit.changed_at.desc())).all()
        return [{"old_status": x.old_status, "new_status": x.new_status,
                 "note": x.note, "changed_at": x.changed_at} for x in rows]

    @app.get("/api/v1/trends", tags=["analytics"])
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
