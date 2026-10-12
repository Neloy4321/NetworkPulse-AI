"""Explicit, tested schema migration entry point for SQLite and PostgreSQL."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

LATEST = "0002_counter_integrity"
BASELINE = "0001_legacy_baseline"
ROOT = Path(__file__).resolve().parent.parent


def _sqlite_path(database_url: str) -> Path | None:
    if not database_url.startswith("sqlite:///"):
        return None
    path = database_url[len("sqlite:///"):].split("?", 1)[0]
    if not path or path == ":memory:":
        return None
    return Path(path)


def _config(connection):
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "alembic"))
    config.attributes["connection"] = connection
    return config


def database_version(database_url: str) -> dict:
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            tables = inspect(connection).get_table_names()
            if "alembic_version" not in tables:
                return {"revision": None, "expected": LATEST, "legacy_detected": "network_events" in tables}
            revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()
            return {"revision": revision, "expected": LATEST, "ready": revision == LATEST}
    finally:
        engine.dispose()


def upgrade_database(database_url: str) -> dict:
    if not database_url.startswith(("sqlite:", "postgresql+psycopg:", "postgresql:")):
        raise ValueError("Migrations support SQLite and PostgreSQL only")
    path = _sqlite_path(database_url)
    backup = None
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size > 0:
            info = database_version(database_url)
            if info.get("revision") != LATEST:
                backup = path.with_name(path.name + ".pre-migration-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f") + ".bak")
                with sqlite3.connect(path) as src, sqlite3.connect(backup) as dest:
                    src.backup(dest)
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            config = _config(connection)
            tables = set(inspect(connection).get_table_names())
            if "alembic_version" not in tables and "network_events" in tables:
                # Only recognize exact v0.1 tables; never stamp a partial or unknown DB.
                if not {"network_events", "alerts", "alert_audit"} <= tables:
                    raise RuntimeError("Incomplete legacy schema: refusing to stamp")
                cols = {c["name"]: c for c in inspect(connection).get_columns("network_events")}
                if not {"id", "timestamp", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"} <= cols.keys():
                    raise RuntimeError("Unknown legacy schema: refusing to stamp")
                if connection.dialect.name == "postgresql" and any(
                    "BIGINT" in str(cols[k]["type"]).upper() for k in ("orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts")
                ):
                    raise RuntimeError("Unknown modern unversioned schema: refusing to stamp")
                command.stamp(config, BASELINE)
            command.upgrade(config, "head")
        result = database_version(database_url)
        if result.get("revision") != LATEST:
            raise RuntimeError("Migration didn't reach expected revision")
        return {**result, "sqlite_backup": str(backup) if backup else None}
    finally:
        engine.dispose()


def backup_sqlite(database_url: str, destination: Path) -> dict:
    """Make a consistent, explicit SQLite backup via the database backup API."""
    path = _sqlite_path(database_url)
    if path is None or not path.exists():
        raise ValueError("SQLite database file must exist; PostgreSQL needs pg_dump")
    destination = destination.resolve()
    if destination == path.resolve() or destination.exists():
        raise ValueError("Backup path must be new and different from the source")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as src, sqlite3.connect(destination) as dest:
        src.backup(dest)
    return {"backup": str(destination), "source": str(path.resolve())}
