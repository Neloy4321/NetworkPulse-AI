"""SQLAlchemy 2 data store: deduplicated events, durable alerts and audit trail."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import BigInteger, DateTime, Float, ForeignKey, Index, Integer, JSON, String, create_engine, event, func, inspect, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker


# SQLite INTEGER retains its native signed 64-bit range and identity semantics.
COUNTER_TYPE = BigInteger().with_variant(Integer(), "sqlite")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class NetworkEvent(Base):
    __tablename__ = "network_events"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(30), nullable=False)
    uid: Mapped[str | None] = mapped_column(String(160))
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    src_port: Mapped[int] = mapped_column(Integer)
    dst_port: Mapped[int] = mapped_column(Integer)
    proto: Mapped[str] = mapped_column(String(12))
    duration: Mapped[float] = mapped_column(Float)
    orig_bytes: Mapped[int] = mapped_column(COUNTER_TYPE)
    resp_bytes: Mapped[int] = mapped_column(COUNTER_TYPE)
    orig_pkts: Mapped[int] = mapped_column(COUNTER_TYPE)
    resp_pkts: Mapped[int] = mapped_column(COUNTER_TYPE)
    conn_state: Mapped[str] = mapped_column(String(24))
    anomaly_score: Mapped[float] = mapped_column(Float)
    risk: Mapped[int] = mapped_column(Integer)
    anomalous: Mapped[bool] = mapped_column(default=False, index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    alert: Mapped[Alert | None] = relationship(back_populates="event", uselist=False)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("network_events.id"), unique=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open", index=True)
    reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    assigned_to: Mapped[str | None] = mapped_column(String(150))
    notes: Mapped[list[AlertNote]] = relationship(back_populates="alert")
    event: Mapped[NetworkEvent] = relationship(back_populates="alert")
    history: Mapped[list[AlertAudit]] = relationship(back_populates="alert")


class AlertAudit(Base):
    __tablename__ = "alert_audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), nullable=False, index=True)
    old_status: Mapped[str] = mapped_column(String(20))
    new_status: Mapped[str] = mapped_column(String(20))
    note: Mapped[str] = mapped_column(String(1500))
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    actor: Mapped[str | None] = mapped_column(String(150))
    alert: Mapped[Alert] = relationship(back_populates="history")


class AlertNote(Base):
    __tablename__ = "alert_notes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), nullable=False)
    actor: Mapped[str] = mapped_column(String(150), nullable=False)
    note: Mapped[str] = mapped_column(String(1500), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    alert: Mapped[Alert] = relationship(back_populates="notes")


Index("idx_alert_assignee", Alert.assigned_to)
Index("idx_alert_notes_alert_date", AlertNote.alert_id, AlertNote.created_at)
Index("idx_flow_timestamp_src", NetworkEvent.timestamp.desc(), NetworkEvent.src_ip)
Index("idx_flow_anomalous_time", NetworkEvent.anomalous, NetworkEvent.timestamp.desc())
Index("idx_flow_src_timestamp", NetworkEvent.src_ip, NetworkEvent.timestamp.desc())
Index("idx_alert_status_created", Alert.status, Alert.created_at.desc())


def build_sessions(database_url: str) -> sessionmaker[Session]:
    options: dict[str, Any] = {"future": True, "pool_pre_ping": True}
    if database_url.startswith("sqlite"):
        options["connect_args"] = {"check_same_thread": False}
        if database_url.startswith("sqlite:///"):
            location = database_url[len("sqlite:///"):].split("?", 1)[0]
            if location not in {":memory:", ""}:
                Path(location).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(database_url, **options)
    if database_url.startswith("sqlite"):
        # SQLite foreign key checks are off by default on many installations.
        @event.listens_for(engine, "connect")
        def enable_foreign_keys(dbapi_connection, _record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    # Never silently mutate a live database schema on API startup.
    # Run `networkpulse db upgrade` before bootstrap/API startup.
    inspector = inspect(engine)
    if "alembic_version" not in inspector.get_table_names():
        engine.dispose()
        raise RuntimeError("Database is not migrated; run: networkpulse db upgrade")
    with engine.connect() as connection:
        version = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()
    if version != "0003_soc_accountability":
        engine.dispose()
        raise RuntimeError("Database migration required; run: networkpulse db upgrade")
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


def counts(session: Session) -> dict:
    events = session.scalar(select(func.count(NetworkEvent.id))) or 0
    alerts = session.scalar(select(func.count(Alert.id))) or 0
    open_alerts = session.scalar(select(func.count(Alert.id)).where(Alert.status == "open")) or 0
    active_alerts = session.scalar(select(func.count(Alert.id)).where(Alert.status == "investigating")) or 0
    risk_avg = session.scalar(select(func.avg(NetworkEvent.risk))) or 0.0
    sources = session.execute(
        select(NetworkEvent.proto, func.count(NetworkEvent.id)).group_by(NetworkEvent.proto)
    ).all()
    return {
        "flows": events, "alerts": alerts, "open_alerts": open_alerts,
        "investigating_alerts": active_alerts, "mean_risk": round(float(risk_avg), 1),
        "protocols": {str(key): int(value) for key, value in sources},
    }
