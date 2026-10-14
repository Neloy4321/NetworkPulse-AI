"""NetworkPulse API. Read-only dashboard endpoints; authenticated mutation endpoints."""

from __future__ import annotations

import secrets
import csv
import io
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from networkpulse.config import Settings
from networkpulse.security.oidc import Principal, TokenVerifier
from networkpulse.security.browser_login import BrowserLogin, STATE_COOKIE, SESSION_COOKIE
from networkpulse.security.limits import security_middleware_factory
from networkpulse.security.csv_safety import safe_spreadsheet_cell
from networkpulse.observability import metric_middleware, exporter, INGEST_TOTAL, ALERT_ACTIONS, MODEL_INFERENCE
import time
from networkpulse.detector import Detector
from networkpulse.schemas import (
    AlertPatch, AlertAssignment, AnalystNote, BehaviorFindingPatch,
    BehaviorIncidentPatch, FlowBatch,
)
from networkpulse.service import change_alert, ingest
from networkpulse.storage import (
    Alert, AlertAudit, AlertNote, BehaviorFinding, BehaviorFindingAudit,
    BehaviorIncident, BehaviorIncidentAudit,
    MLOpsDriftRun, NetworkEvent, build_sessions, counts,
)

STATIC = Path(__file__).parent / "static"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    if settings.deployment_mode == "production" and settings.auth_mode != "oidc":
        raise ValueError("Production API requires OIDC access control")
    if settings.deployment_mode == "production" and not settings.security_redis_url:
        raise ValueError("Production API requires Redis-backed security")
    if settings.browser_oidc_enabled and settings.auth_mode != "oidc":
        raise ValueError("Browser login requires OIDC mode")
    if settings.deployment_mode == "production":
        if not settings.browser_oidc_enabled:
            raise ValueError("Production API requires browser OIDC login")
        if not settings.model_sha256 or not settings.model_path.is_file():
            raise ValueError("Production API requires checksum-pinned trusted model")
        from networkpulse.security.deployment import validate_production_urls
        validate_production_urls(settings)
    redis_client = None
    distributed_limiter = None
    if settings.security_redis_url:
        import redis
        from networkpulse.security.distributed_limit import DistributedLimiter
        redis_client = redis.Redis.from_url(
            settings.security_redis_url, socket_connect_timeout=2,
            socket_timeout=2, retry_on_timeout=False
        )
        redis_client.ping()  # Fail startup if the security store is unavailable.
        distributed_limiter = DistributedLimiter(
            redis_client, settings.mutation_rate_per_minute,
            settings.global_rate_per_minute
        )
    make_session = build_sessions(settings.database_url)
    # Persist models trained offline; do not auto-train on incoming production data.
    if settings.model_sha256 and settings.model_path.is_file():
        from networkpulse.model_registry import sha256
        if len(settings.model_sha256) != 64 or sha256(settings.model_path) != settings.model_sha256:
            raise ValueError('Trusted model artifact SHA-256 verification failed')
    model = Detector.load(settings.model_path) if settings.model_path.is_file() else None
    # Production deployment must never accidentally serve the developer's
    # seeded model. The source metadata is a minimum guard, not an attestation:
    # operators still must verify independent validation and provenance.
    if settings.deployment_mode == "production":
        if model is None or "synthetic" in str(model.metadata.get("source", "")).lower():
            raise ValueError("Production refuses missing or synthetic/demo model artifacts")
    verifier = (TokenVerifier(settings.oidc_issuer, settings.oidc_audience,
                              settings.oidc_jwks_url, settings.oidc_role_claim)
                if settings.auth_mode == "oidc" else None)

    browser = (BrowserLogin(
        redis_client, settings.oidc_issuer, settings.oidc_auth_url,
        settings.oidc_token_url, settings.oidc_client_id, settings.public_origin,
    ) if settings.browser_oidc_enabled else None)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        try:
            yield
        finally:
            make_session.kw["bind"].dispose()
            if redis_client is not None:
                redis_client.close()

    app = FastAPI(
        lifespan=lifespan,
        title="NetworkPulse AI", version="0.5.0",
        description="Flow observability, anomaly triage and auditable review. Not an IDS replacement.",
        # Do not rely solely on Caddy to hide implementation metadata: the
        # application must remain safe if the reverse proxy is bypassed.
        docs_url=None if settings.deployment_mode == "production" else "/docs",
        redoc_url=None if settings.deployment_mode == "production" else "/redoc",
        openapi_url=None if settings.deployment_mode == "production" else "/openapi.json",
    )

    app.state.browser_login = browser
    app.middleware("http")(metric_middleware)
    app.middleware("http")(security_middleware_factory(
        max_body_bytes=settings.max_body_bytes, per_minute=settings.mutation_rate_per_minute,
        distributed_limiter=distributed_limiter))

    def require_identity(request: Request,
                         authorization: Annotated[str | None, Header()] = None,
                         x_csrf_token: Annotated[str | None, Header()] = None) -> Principal:
        if verifier is None:
            return Principal(subject="local-operator", role="admin")
        if authorization is not None:
            if not authorization.startswith("Bearer "):
                raise HTTPException(401, detail="Bearer access token required")
            return verifier.verify(authorization[len("Bearer "):])
        if browser is not None:
            session = browser.session(request.cookies.get(SESSION_COOKIE))
            if session is not None:
                principal = verifier.verify(session["token"])
                if request.method in {"POST", "PATCH", "PUT", "DELETE"}:
                    origin = request.headers.get("origin")
                    if (origin != browser.origin or not x_csrf_token or
                            not secrets.compare_digest(session["csrf"], x_csrf_token)):
                        raise HTTPException(403, detail="Invalid browser CSRF or Origin")
                return principal
            if request.url.path == "/":
                raise HTTPException(307, headers={"Location": "/auth/login"},
                                    detail="Sign-in required")
        raise HTTPException(401, detail="OIDC bearer access token or session required")

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

    @app.get("/auth/login", include_in_schema=False)
    def browser_login(request: Request):
        if browser is None:
            raise HTTPException(404, detail="Browser login disabled")
        # GET login attempts also consume a shared Redis admission slot.
        if distributed_limiter is not None and not distributed_limiter.admit(
            "oidc-login:" + (request.client.host if request.client else "unknown")
        ):
            raise HTTPException(429, detail="Login attempt budget exceeded")
        location, state = browser.start()
        response = RedirectResponse(location, status_code=302)
        response.set_cookie(
            STATE_COOKIE, state, max_age=300, secure=True, httponly=True,
            samesite="lax", path="/",
        )
        return response

    @app.get("/auth/callback", include_in_schema=False)
    async def browser_callback(request: Request, code: str = Query(min_length=8, max_length=4096),
                               state: str = Query(min_length=16, max_length=128)):
        if browser is None:
            raise HTTPException(404, detail="Browser login disabled")
        if distributed_limiter is not None and not distributed_limiter.admit(
            "oidc-callback:" + (request.client.host if request.client else "unknown")
        ):
            raise HTTPException(429, detail="Login callback budget exceeded")
        pending = browser.consume(state, request.cookies.get(STATE_COOKIE))
        token, ttl = await browser.exchange(code, pending, verifier)
        session_id = browser.create_session(token, ttl)
        response = RedirectResponse("/", status_code=303)
        response.delete_cookie(STATE_COOKIE, path="/", secure=True, httponly=True)
        response.set_cookie(
            SESSION_COOKIE, session_id, max_age=ttl, secure=True, httponly=True,
            samesite="lax", path="/",
        )
        return response

    @app.get("/auth/session", include_in_schema=False)
    def browser_session(request: Request):
        if browser is None:
            raise HTTPException(404, detail="Browser login disabled")
        entry = browser.session(request.cookies.get(SESSION_COOKIE))
        if entry is None:
            raise HTTPException(401, detail="Session expired")
        principal = verifier.verify(entry["token"])
        return {"subject": principal.subject, "role": principal.role, "csrf_token": entry["csrf"]}

    @app.post("/auth/logout", include_in_schema=False)
    def browser_logout(request: Request, principal: Principal = Depends(require_identity)):
        if browser is None or not request.cookies.get(SESSION_COOKIE):
            raise HTTPException(401, detail="Browser session required")
        browser.logout(request.cookies.get(SESSION_COOKIE))
        response = Response(status_code=204)
        response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True)
        return response

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
        return exporter(settings.redis_metrics_url)

    @app.get("/health/live", tags=["operations"])
    def liveness():
        return {"status": "ok"}

    @app.get("/health/ready", tags=["operations"])
    def readiness():
        if model is None:
            raise HTTPException(503, detail="Model artifact unavailable")
        with make_session() as session:
            counts(session)
        # Public readiness probes must not expose local training paths or provenance.
        return {"status": "ready"}

    @app.get("/api/v1/mlops/drift-runs", tags=["model"])
    def mlops_drift_runs(
        limit: int = Query(20, ge=1, le=100),
        offset: int = Query(0, ge=0, le=10000),
        principal: Principal = Depends(read_scope),
        db: Session = Depends(get_db),
    ):
        # Drift aggregates and model fingerprint are operational metadata:
        # restrict to administrators even though the API is read-only.
        principal.require("admin")
        found = db.scalars(select(MLOpsDriftRun).order_by(
            MLOpsDriftRun.window_end.desc(), MLOpsDriftRun.created_at.desc(),
            MLOpsDriftRun.id.asc(),
        ).offset(offset).limit(limit + 1)).all()
        return {
            "runs": [{
                "id": item.id, "model_sha256": item.model_sha256,
                "window_start_utc": item.window_start,
                "window_end_utc": item.window_end,
                "input_fingerprint_sha256": item.input_fingerprint,
                "flow_count": item.flow_count,
                "flagged_flows": item.flagged_flows,
                "drift_status": item.drift_status,
                "alert_budget_exceeded": item.alert_budget_exceeded,
                "worst_psi": item.worst_psi,
                "created_at": item.created_at,
                "report": item.report,
            } for item in found[:limit]],
            "has_more": len(found) > limit,
            "warning": "Unlabeled feature drift is not observed detection accuracy.",
        }

    @app.get("/api/v1/intelligence/behavior", tags=["analytics"],
             dependencies=[Depends(read_scope)])
    def behavior_windows(
        window_minutes: int = Query(5, ge=1, le=5),
        lookback_minutes: int = Query(60, ge=1, le=1440),
        until: datetime | None = None,
        src_ip: str | None = Query(default=None, max_length=45),
        limit: int = Query(30, ge=1, le=100),
        offset: int = Query(0, ge=0, le=10000),
        min_distinct_ports: int = Query(12, ge=2, le=65536),
        min_distinct_destinations: int = Query(8, ge=2, le=10000),
        burst_flows_per_minute: int = Query(120, ge=10, le=100000),
        db: Session = Depends(get_db),
    ):
        """Actual persisted flow aggregation, not a separate benchmark-only path."""
        import ipaddress
        from networkpulse.behavior import activity_windows
        if window_minutes not in (1, 5):
            raise HTTPException(422, detail="window_minutes must be 1 or 5")
        if until is not None and (until.tzinfo is None or until.utcoffset() is None):
            raise HTTPException(422, detail="until must be timezone-aware")
        if src_ip:
            try:
                src_ip = str(ipaddress.ip_address(src_ip))
            except ValueError as exc:
                raise HTTPException(422, detail="Invalid source IP address") from exc
        return activity_windows(
            db, window_minutes=window_minutes, lookback_minutes=lookback_minutes,
            until=until, src_ip=src_ip, limit=limit, offset=offset,
            min_distinct_ports=min_distinct_ports,
            min_distinct_destinations=min_distinct_destinations,
            burst_flows_per_minute=burst_flows_per_minute,
        )

    def behavior_case_dict(record: BehaviorFinding) -> dict:
        return {
            "id": record.id, "source_ip": record.source_ip,
            "window_start_utc": record.window_start,
            "window_minutes": record.window_minutes,
            "patterns": record.patterns, "flow_count": record.flow_count,
            "distinct_destination_ports": record.destination_ports,
            "distinct_destination_hosts": record.destination_hosts,
            "flagged_flows": record.flagged_flows,
            "severity": record.severity, "status": record.status,
            "assigned_to": record.assigned_to,
            "created_at": record.created_at, "updated_at": record.updated_at,
            "evidence_type": "correlated_flow_metadata_heuristic_only",
        }

    @app.get("/api/v1/intelligence/findings", tags=["analytics"],
             dependencies=[Depends(read_scope)])
    def list_behavior_findings(
        limit: int = Query(30, ge=1, le=100),
        offset: int = Query(0, ge=0, le=10000),
        status: Literal["open", "investigating", "resolved", "false_positive"] | None = None,
        source_ip: str | None = Query(default=None, max_length=45),
        db: Session = Depends(get_db),
    ):
        import ipaddress
        query = select(BehaviorFinding)
        if status:
            query = query.where(BehaviorFinding.status == status)
        if source_ip:
            try:
                normalized = str(ipaddress.ip_address(source_ip))
            except ValueError as exc:
                raise HTTPException(422, detail="Invalid source address") from exc
            query = query.where(BehaviorFinding.source_ip == normalized)
        records = db.scalars(query.order_by(
            BehaviorFinding.window_start.desc(), BehaviorFinding.id.asc(),
        ).offset(offset).limit(limit + 1)).all()
        return {
            "findings": [behavior_case_dict(f) for f in records[:limit]],
            "has_more": len(records) > limit,
            "disclaimer": "Heuristic correlation; a finding is not a confirmed intrusion.",
        }

    @app.get("/api/v1/intelligence/findings/{finding_id}/history",
             tags=["analytics"], dependencies=[Depends(read_scope)])
    def behavior_finding_history(finding_id: str, db: Session = Depends(get_db)):
        if db.get(BehaviorFinding, finding_id) is None:
            raise HTTPException(404, detail="Behavior finding not found")
        rows = db.scalars(select(BehaviorFindingAudit).where(
            BehaviorFindingAudit.finding_id == finding_id,
        ).order_by(BehaviorFindingAudit.changed_at.desc(),
                   BehaviorFindingAudit.id.desc()).limit(100)).all()
        return [{
            "actor": row.actor, "old_status": row.old_status,
            "new_status": row.new_status, "old_assignee": row.old_assignee,
            "new_assignee": row.new_assignee, "note": row.note,
            "changed_at": row.changed_at,
        } for row in rows]

    @app.patch("/api/v1/intelligence/findings/{finding_id}",
               tags=["analytics"], dependencies=[Depends(require_api_key)])
    def update_behavior_finding(
        finding_id: str, payload: BehaviorFindingPatch,
        principal: Principal = Depends(analyst_scope),
        db: Session = Depends(get_db),
    ):
        if not ({"status", "assigned_to"} & payload.model_fields_set):
            raise HTTPException(422, detail="Specify a status or assignment")
        if "status" in payload.model_fields_set and payload.status is None:
            raise HTTPException(422, detail="Status cannot be null")
        record = db.scalar(select(BehaviorFinding).where(
            BehaviorFinding.id == finding_id,
        ).with_for_update())
        if record is None:
            raise HTTPException(404, detail="Behavior finding not found")
        old_status, old_assignee = record.status, record.assigned_to
        if "status" in payload.model_fields_set:
            record.status = payload.status
        if "assigned_to" in payload.model_fields_set:
            record.assigned_to = payload.assigned_to
        from networkpulse.storage import now_utc
        record.updated_at = now_utc()
        db.add(BehaviorFindingAudit(
            finding_id=record.id, actor=principal.subject[:150],
            old_status=old_status, new_status=record.status,
            old_assignee=old_assignee, new_assignee=record.assigned_to,
            note=payload.note,
        ))
        db.commit()
        return behavior_case_dict(record)

    def incident_as_dict(incident: BehaviorIncident) -> dict:
        return {
            "id": incident.id, "source_ip": incident.source_ip,
            "hour_start_utc": incident.hour_start,
            "first_seen_utc": incident.first_seen,
            "last_seen_utc": incident.last_seen,
            "window_count": incident.window_count,
            "flow_count": incident.total_flows,
            "flagged_flows": incident.flagged_flows,
            "signals": incident.patterns, "severity": incident.severity,
            "status": incident.status, "assigned_to": incident.assigned_to,
            "created_at": incident.created_at, "updated_at": incident.updated_at,
            "evidence_type": "multi_window_source_hour_heuristic",
        }

    @app.get("/api/v1/intelligence/incidents", tags=["analytics"],
             dependencies=[Depends(read_scope)])
    def list_incidents(
        limit: int = Query(30, ge=1, le=100),
        offset: int = Query(0, ge=0, le=10000),
        status: Literal["open", "investigating", "resolved", "false_positive"] | None = None,
        source_ip: str | None = Query(default=None, max_length=45),
        db: Session = Depends(get_db),
    ):
        import ipaddress
        q = select(BehaviorIncident)
        if status:
            q = q.where(BehaviorIncident.status == status)
        if source_ip:
            try:
                normalized = str(ipaddress.ip_address(source_ip))
            except ValueError as exc:
                raise HTTPException(422, detail="Invalid source address") from exc
            q = q.where(BehaviorIncident.source_ip == normalized)
        items = db.scalars(q.order_by(
            BehaviorIncident.hour_start.desc(), BehaviorIncident.id.asc(),
        ).offset(offset).limit(limit + 1)).all()
        return {
            "incidents": [incident_as_dict(item) for item in items[:limit]],
            "has_more": len(items) > limit,
            "disclaimer": "Hourly source-correlated heuristics, not verified attacks.",
        }

    @app.get("/api/v1/intelligence/incidents/{incident_id}/evidence",
             tags=["analytics"], dependencies=[Depends(read_scope)])
    def incident_evidence(incident_id: str, db: Session = Depends(get_db)):
        item = db.get(BehaviorIncident, incident_id)
        if item is None:
            raise HTTPException(404, detail="Incident not found")
        findings = list(db.scalars(select(BehaviorFinding).where(
            BehaviorFinding.id.in_(item.finding_ids),
        ).order_by(BehaviorFinding.window_start.asc(), BehaviorFinding.id.asc())))
        if len(findings) != len(item.finding_ids):
            raise HTTPException(409, detail="Incident evidence incomplete; restore retained finding data")
        return {
            "incident": incident_as_dict(item),
            "timeline": [behavior_case_dict(f) for f in findings],
            "warning": "Evidence windows are heuristics; no proof of compromise.",
        }

    @app.get("/api/v1/intelligence/incidents/{incident_id}/history",
             tags=["analytics"], dependencies=[Depends(read_scope)])
    def incident_history(incident_id: str, db: Session = Depends(get_db)):
        if db.get(BehaviorIncident, incident_id) is None:
            raise HTTPException(404, detail="Incident not found")
        rows = db.scalars(select(BehaviorIncidentAudit).where(
            BehaviorIncidentAudit.incident_id == incident_id,
        ).order_by(BehaviorIncidentAudit.changed_at.desc(),
                   BehaviorIncidentAudit.id.desc()).limit(100)).all()
        return [{
            "actor": row.actor, "old_status": row.old_status,
            "new_status": row.new_status, "old_assignee": row.old_assignee,
            "new_assignee": row.new_assignee, "note": row.note,
            "changed_at": row.changed_at,
        } for row in rows]

    @app.patch("/api/v1/intelligence/incidents/{incident_id}",
               tags=["analytics"], dependencies=[Depends(require_api_key)])
    def update_incident(
        incident_id: str, payload: BehaviorIncidentPatch,
        principal: Principal = Depends(analyst_scope),
        db: Session = Depends(get_db),
    ):
        if not ({"status", "assigned_to"} & payload.model_fields_set):
            raise HTTPException(422, detail="Specify a status or assignment")
        if "status" in payload.model_fields_set and payload.status is None:
            raise HTTPException(422, detail="Status cannot be null")
        item = db.scalar(select(BehaviorIncident).where(
            BehaviorIncident.id == incident_id,
        ).with_for_update())
        if item is None:
            raise HTTPException(404, detail="Incident not found")
        previous_status, previous_owner = item.status, item.assigned_to
        if "status" in payload.model_fields_set:
            item.status = payload.status
        if "assigned_to" in payload.model_fields_set:
            item.assigned_to = payload.assigned_to
        from networkpulse.storage import now_utc
        item.updated_at = now_utc()
        db.add(BehaviorIncidentAudit(
            incident_id=item.id, actor=principal.subject[:150],
            old_status=previous_status, new_status=item.status,
            old_assignee=previous_owner, new_assignee=item.assigned_to,
            note=payload.note,
        ))
        db.commit()
        return incident_as_dict(item)

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
            writer.writerow([safe_spreadsheet_cell(cell) for cell in record])
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
