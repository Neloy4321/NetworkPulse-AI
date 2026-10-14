"""Operator-controlled database snapshots and isolated restore drills.

Backups are not usable merely because their bytes exist. Verify a manifest
checksum, restore into a pre-existing EMPTY, separately named drill database
and check schema, row counts, FK consistency and SOC audit lineage.

PostgreSQL uses native pg_dump/pg_restore custom-format archives, never
application SQL exports. No destructive restore to an application database.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

from networkpulse.migrations import LATEST, _sqlite_path, database_version

TABLES = (
    "network_events", "alerts", "alert_audit", "alert_notes",
    "behavior_findings", "behavior_finding_audit",
    "behavior_incidents", "behavior_incident_audit",
    "mlops_drift_runs",
)
FORMAT = "networkpulse-db-snapshot-v1"


def _sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


def _db_kind(url: str) -> str:
    if url.startswith("sqlite:///"):
        return "sqlite"
    if url.startswith(("postgresql+psycopg://", "postgresql://")):
        return "postgresql"
    raise ValueError("Recovery supports SQLite files and PostgreSQL only")


def _postgres_args(url: str) -> tuple[dict[str, str], str]:
    parsed = make_url(url)
    if parsed.get_backend_name() != "postgresql":
        raise ValueError("Expected a PostgreSQL URL")
    if not parsed.database or not parsed.host:
        raise ValueError("PostgreSQL URL needs explicit database and host")
    if parsed.query and set(parsed.query) - {"sslmode"}:
        raise ValueError("PostgreSQL recovery URL contains unsupported options")
    env = os.environ.copy()
    env.update({
        "PGHOST": parsed.host, "PGPORT": str(parsed.port or 5432),
        "PGUSER": parsed.username or "", "PGDATABASE": parsed.database,
        "PGCONNECT_TIMEOUT": "10",
    })
    if parsed.password is not None:
        env["PGPASSWORD"] = parsed.password
    if "sslmode" in parsed.query:
        env["PGSSLMODE"] = str(parsed.query["sslmode"])
    return env, parsed.database


def _run(binary: str, args: list[str], env: dict[str, str]) -> None:
    if shutil.which(binary) is None:
        raise RuntimeError(f"Required PostgreSQL client binary is missing: {binary}")
    try:
        outcome = subprocess.run(
            [binary, *args], env=env, capture_output=True, text=True,
            check=False, timeout=180,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{binary} exceeded bounded execution time") from exc
    if outcome.returncode:
        # stderr can contain connection details; never echo it, particularly
        # when an operator supplies a password or private hostname.
        raise RuntimeError(f"{binary} failed (exit {outcome.returncode}); inspect private DB logs")


def _reserve(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError("Snapshot destination already exists; never overwrite a backup")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)


def create_snapshot(url: str, destination: Path) -> dict:
    """Write an unencrypted, mode-0600 snapshot + checksum manifest.

    Run on an operator-controlled host with secure disk and private backups.
    A DB revision mismatch fails *before* writing; no migration occurs.
    """
    kind = _db_kind(url)
    state = database_version(url)
    if state.get("revision") != LATEST:
        raise ValueError("Database must be migrated before its recovery snapshot")
    target = Path(destination).resolve()
    if target.name.endswith(".json"):
        raise ValueError("Backup output must not be a JSON manifest filename")
    manifest_path = Path(str(target) + ".manifest.json")
    if target.exists() or manifest_path.exists():
        raise FileExistsError("Existing backup/manifest cannot be overwritten")
    path = _sqlite_path(url)
    if path and target == path.resolve():
        raise ValueError("Cannot back up a SQLite database onto itself")
    _reserve(target)
    try:
        if kind == "sqlite":
            assert path is not None
            with sqlite3.connect(path) as source, sqlite3.connect(target) as copied:
                source.backup(copied)
            backup_format = "sqlite-backup-api"
        else:
            env, name = _postgres_args(url)
            _run("pg_dump", [
                "--format=custom", "--no-owner", "--no-acl",
                "--file", str(target), "--dbname", name,
            ], env)
            backup_format = "pg_dump-custom"
        if not target.stat().st_size:
            raise RuntimeError("Snapshot is empty")
        result = {
            "format": FORMAT, "engine": kind,
            "dump_format": backup_format,
            "schema_revision": LATEST,
            "backup_file": target.name,
            "backup_sha256": _sha256(target),
            "backup_bytes": target.stat().st_size,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "encrypted_by_application": False,
            "note": "Checksum protects against corruption, not source authenticity; secure and encrypt at rest.",
        }
        _reserve(manifest_path)
        with manifest_path.open("w", encoding="utf-8") as handle:
            json.dump(result, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        return {
            "backup": str(target), "manifest": str(manifest_path),
            "backup_sha256": result["backup_sha256"],
            "schema_revision": LATEST,
            "warning": "Unencrypted database backup; protect as sensitive production data.",
        }
    except BaseException:
        target.unlink(missing_ok=True)
        manifest_path.unlink(missing_ok=True)
        raise


def verify_snapshot(backup: Path, manifest_path: Path | None = None) -> dict:
    backup = Path(backup).resolve()
    companion = Path(manifest_path).resolve() if manifest_path else Path(str(backup) + ".manifest.json")
    content = json.loads(companion.read_text(encoding="utf-8"))
    if not isinstance(content, dict) or content.get("format") != FORMAT:
        raise ValueError("Unsupported recovery manifest")
    if content.get("engine") not in ("sqlite", "postgresql"):
        raise ValueError("Unsupported snapshot engine")
    if content.get("schema_revision") != LATEST:
        raise ValueError("Snapshot revision is not current; plan a separate migration")
    if content.get("backup_file") != backup.name:
        raise ValueError("Snapshot filename and manifest disagree")
    if backup.stat().st_size != content.get("backup_bytes"):
        raise ValueError("Snapshot file size mismatch")
    actual = _sha256(backup)
    if actual != content.get("backup_sha256"):
        raise ValueError("Snapshot checksum mismatch")
    return {
        "verified": True, "engine": content["engine"],
        "schema_revision": content["schema_revision"],
        "backup_sha256": actual,
        "backup_bytes": backup.stat().st_size,
        "warning": "Integrity verified, but file/manifest are not cryptographically signed.",
    }


def _summarize_restored(url: str) -> dict:
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            names = set(inspect(connection).get_table_names())
            missing = set(TABLES) - names
            if missing:
                raise RuntimeError("Restore missing tables: " + ", ".join(sorted(missing)))
            foreign_keys = [
                ("alerts", "event_id", "network_events", "id"),
                ("alert_audit", "alert_id", "alerts", "id"),
                ("alert_notes", "alert_id", "alerts", "id"),
                ("behavior_finding_audit", "finding_id", "behavior_findings", "id"),
                ("behavior_incident_audit", "incident_id", "behavior_incidents", "id"),
            ]
            counts = {}
            for table in TABLES:
                # Whitelisted identifiers; never interpolate user-supplied SQL.
                counts[table] = connection.execute(text(f'SELECT count(*) FROM "{table}"')).scalar_one()
            for child, fk, parent, pk in foreign_keys:
                bad = connection.execute(text(
                    f'SELECT count(*) FROM "{child}" c LEFT JOIN "{parent}" p '
                    f'ON c."{fk}"=p."{pk}" WHERE p."{pk}" IS NULL'
                )).scalar_one()
                if bad:
                    raise RuntimeError(f"Restored FK integrity failed: {child}.{fk}")
            if engine.dialect.name == "sqlite":
                corrupted = connection.execute(text("PRAGMA integrity_check")).scalar_one()
                if corrupted != "ok":
                    raise RuntimeError("Restored SQLite integrity_check failed")
                fk_issues = connection.execute(text("PRAGMA foreign_key_check")).fetchall()
                if fk_issues:
                    raise RuntimeError("Restored SQLite foreign_key_check failed")
        revision = database_version(url)["revision"]
        if revision != LATEST:
            raise RuntimeError("Restored Alembic schema revision mismatch")
        return {
            "revision": revision, "counts": counts, "foreign_keys_verified": True,
            "note": "No application model artifact/Redis state is included in a DB snapshot.",
        }
    finally:
        engine.dispose()


def recovery_drill(
    backup: Path, restore_url: str, *, expected_sha256: str,
    confirm_isolated_target: bool = False,
) -> dict:
    """RESTORE only to an empty, distinctly named scratch database.

    This is deliberately not a production restore command. It NEVER drops,
    cleans or overwrites any existing schema or data. Operators own scratch
    DB provisioning/removal and must protect restored sensitive data.
    """
    if not confirm_isolated_target:
        raise ValueError("Explicit isolated recovery-drill consent required")
    verified = verify_snapshot(backup)
    if verified["backup_sha256"] != expected_sha256:
        raise ValueError("Operator-approved backup SHA-256 mismatch")
    kind = _db_kind(restore_url)
    if kind != verified["engine"]:
        raise ValueError("Restore engine must match backup engine")
    target = make_url(restore_url)
    db_name = target.database or ""
    if not ("_drill_" in db_name or db_name.endswith("_drill")):
        raise ValueError("Target database name must explicitly contain _drill_ or end _drill")
    if kind == "sqlite":
        dest = _sqlite_path(restore_url)
        assert dest is not None
        if dest.exists():
            raise ValueError("SQLite drill target must not exist")
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            with sqlite3.connect(Path(backup)) as source, sqlite3.connect(dest) as copied:
                source.backup(copied)
            out = _summarize_restored(restore_url)
        except BaseException:
            dest.unlink(missing_ok=True)
            raise
    else:
        engine = create_engine(restore_url)
        try:
            with engine.connect() as conn:
                if inspect(conn).get_table_names():
                    raise ValueError("PostgreSQL drill target must be completely empty")
        finally:
            engine.dispose()
        env, name = _postgres_args(restore_url)
        # Transactional restore: no incomplete committed schema if pg_restore fails.
        _run("pg_restore", [
            "--single-transaction", "--exit-on-error", "--no-owner", "--no-acl",
            "--dbname", name, str(Path(backup).resolve()),
        ], env)
        out = _summarize_restored(restore_url)
    return {
        "drill": "completed_verified", "source_sha256": verified["backup_sha256"],
        "target_engine": kind, **out,
        "warning": "This is an isolated restore test. Stop applications and use an incident-approved plan for actual recovery.",
    }
