"""AES-256-GCM encrypted Stage B CI snapshot and isolated PostgreSQL restore.

This is a disposable single-run synthetic-data drill, not the production DB
recovery path, multi-host backup system, or a certified RPO/RTO measurement.
An archive is fully authenticated *before* any scratch database is created.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from psycopg import sql

from networkpulse.infra_event_harness import (
    DATABASE_NAME, LabSettings, SyntheticIntegrityHarness, TABLE,
)
from networkpulse.infra_stage_b_restart import owned_container, require_disposable_ci

FORMAT = "networkpulse-stage-b-aes256-gcm-v1"
MAGIC = b"NPB-DR1!"
KEY_ENV = "NETWORKPULSE_STAGE_B_DR_KEY_HEX"
CONSENT = "I_ACCEPT_DISPOSABLE_ENCRYPTED_DR"
TABLE_ID = "public.np_stage_b_synthetic_receipts"
CHUNK = 1024 * 1024


def _json_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _key() -> bytes:
    value = os.environ.get(KEY_ENV, "")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise ValueError("Ephemeral AES-256 key must be 64 hex characters")
    return bytes.fromhex(value)


def _reserve(path: Path):
    # O_EXCL and O_NOFOLLOW prevent replacing an existing file or symlink.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    return os.fdopen(fd, "wb")


def _fingerprint(rows) -> str:
    return hashlib.sha256(_json_bytes({"receipts": [list(r) for r in rows]})).hexdigest()


def _read_rows(conn, run_id: str) -> list:
    with conn.cursor() as cursor:
        cursor.execute(
            f"SELECT event_id, ordinal, payload_sha256 FROM {TABLE} "
            "WHERE run_id=%s ORDER BY ordinal", (run_id,),
        )
        return cursor.fetchall()


def _encrypted_stream(input_stream, output: Path, key: bytes, aad: bytes) -> int:
    """Encrypt a pg_dump stream without writing a plaintext dump to disk."""
    nonce = os.urandom(12)
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    enc.authenticate_additional_data(aad)
    size = 0
    with _reserve(output) as sink:
        sink.write(MAGIC + nonce)
        while block := input_stream.read(CHUNK):
            size += len(block)
            sink.write(enc.update(block))
        sink.write(enc.finalize())
        sink.write(enc.tag)
        sink.flush()
        os.fsync(sink.fileno())
    if size == 0:
        raise RuntimeError("Empty PostgreSQL backup cannot be accepted")
    return size


def _decrypt_verified(archive: Path, scratch_plaintext: Path, manifest: dict,
                      key: bytes) -> None:
    """Reject SHA/AAD/GCM failures before a single restore SQL operation."""
    if archive.name != manifest["archive_name"]:
        raise ValueError("Archive filename differs from manifest")
    if _sha(archive) != manifest["archive_sha256"]:
        raise ValueError("Encrypted archive checksum mismatch")
    aad = _json_bytes(manifest["scope"])
    n = archive.stat().st_size
    if n <= len(MAGIC) + 12 + 16:
        raise ValueError("Truncated encrypted backup")
    try:
        with archive.open("rb") as source:
            if source.read(len(MAGIC)) != MAGIC:
                raise ValueError("Unsupported encrypted archive header")
            nonce = source.read(12)
            source.seek(-16, 2)
            tag = source.read(16)
            source.seek(len(MAGIC) + 12)
            decrypt = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
            decrypt.authenticate_additional_data(aad)
            remaining = n - len(MAGIC) - 12 - 16
            with _reserve(scratch_plaintext) as plaintext:
                while remaining:
                    piece = source.read(min(remaining, CHUNK))
                    if not piece:
                        raise ValueError("Truncated ciphertext")
                    remaining -= len(piece)
                    plaintext.write(decrypt.update(piece))
                plaintext.write(decrypt.finalize())
                plaintext.flush()
                os.fsync(plaintext.fileno())
    except (InvalidTag, ValueError):
        scratch_plaintext.unlink(missing_ok=True)
        raise ValueError("Encrypted backup authentication failed") from None
    except BaseException:
        scratch_plaintext.unlink(missing_ok=True)
        raise


def _subprocess(command: list[str], env: dict, *, stdout=None):
    return subprocess.Popen(
        command, stdout=stdout, stderr=subprocess.DEVNULL,
        env=env,
    )


def _pg_env(settings: LabSettings) -> dict:
    # Credentials are never placed on argv, printed, or persisted to artifacts.
    return {**os.environ, "PGPASSWORD": settings.db_password, "PGCONNECT_TIMEOUT": "8"}


def _pg_params(settings: LabSettings) -> list[str]:
    return ["--host", settings.db_host, "--port", str(settings.db_port),
            "--username", "networkpulse_staging", "--no-password"]


def _backup(settings: LabSettings, destination: Path, manifest_path: Path,
            scope: dict, key: bytes) -> dict:
    if destination.exists() or destination.is_symlink() or manifest_path.exists():
        raise FileExistsError("Refuse to overwrite existing backup artifacts")
    start = time.monotonic()
    command = ["pg_dump", *_pg_params(settings), "--dbname", DATABASE_NAME,
               "--format=custom", "--no-owner", "--no-acl",
               "--table", TABLE_ID]
    process = _subprocess(command, _pg_env(settings), stdout=subprocess.PIPE)
    try:
        assert process.stdout is not None
        count = _encrypted_stream(process.stdout, destination, key, _json_bytes(scope))
        process.stdout.close()
        try:
            rc = process.wait(timeout=90)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise RuntimeError("Bounded PostgreSQL backup time exceeded") from None
        if rc:
            raise RuntimeError("Native PostgreSQL backup command failed")
        manifest = {
            "format": FORMAT, "scope": scope,
            "archive_name": destination.name, "archive_sha256": _sha(destination),
            "encrypted_bytes": destination.stat().st_size,
            "pg_dump_plaintext_bytes_transient": count,
            "created_utc": datetime.now(timezone.utc).isoformat(),
        }
        with _reserve(manifest_path) as stream:
            stream.write(json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        return {"manifest": manifest, "backup_seconds": round(time.monotonic() - start, 3)}
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        destination.unlink(missing_ok=True)
        manifest_path.unlink(missing_ok=True)
        raise


def _restore(settings: LabSettings, scratch_db: str, archive: Path, manifest: dict,
             key: bytes, workdir: Path) -> dict:
    if manifest.get("format") != FORMAT or not isinstance(manifest.get("scope"), dict):
        raise ValueError("Unknown encrypted backup format")
    scope = manifest["scope"]
    if (scope.get("source_database") != DATABASE_NAME or scope.get("table") != TABLE_ID
            or not re.fullmatch(r"[0-9a-f]{32}", str(scope.get("run_id", "")))):
        raise ValueError("Source snapshot scope does not match isolated Stage B")
    if not re.fullmatch(r"networkpulse_stageb_drill_[0-9a-f]{12}", scratch_db):
        raise ValueError("Scratch restore must target a distinct random CI database")
    plaintext = workdir / "authenticated-transient.pgcustom"
    start = time.monotonic()
    created = False
    source = None
    try:
        # MUST authenticate full archive before CREATE DATABASE/pg_restore.
        _decrypt_verified(archive, plaintext, manifest, key)
        source = _connect(settings, DATABASE_NAME)
        with source.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname=%s", (scratch_db,))
            if cur.fetchone():
                raise ValueError("Scratch restore target already exists")
            cur.execute(sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(
                sql.Identifier(scratch_db)
            ))
            created = True
        result = subprocess.run(
            ["pg_restore", *_pg_params(settings), "--dbname", scratch_db,
             "--single-transaction", "--exit-on-error", "--no-owner", "--no-acl",
             str(plaintext)],
            env=_pg_env(settings), stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, check=False, timeout=90,
        )
        if result.returncode:
            raise RuntimeError("Native PostgreSQL scratch restore failed")
        target = _connect(settings, scratch_db)
        try:
            rows = _read_rows(target, scope["run_id"])
            with target.cursor() as cur:
                cur.execute(f"SELECT count(*) FROM {TABLE}")
                total = cur.fetchone()[0]
            verified = (
                total == scope["row_count"]
                and len(rows) == scope["row_count"]
                and _fingerprint(rows) == scope["fingerprint"]
                and all(
                    event_id == f"{scope['run_id']}:{index:06d}"
                    for index, (event_id, _, _) in enumerate(rows)
                )
            )
            if not verified:
                raise RuntimeError("Restored receipt fingerprint or count mismatch")
        finally:
            target.close()
        return {"restored_receipts": len(rows), "verified": True,
                "restore_seconds": round(time.monotonic() - start, 3),
                "isolated_database": "random_per_run_scratch_only"}
    finally:
        plaintext.unlink(missing_ok=True)
        if source is not None:
            try:
                if created:
                    with source.cursor() as cur:
                        cur.execute(sql.SQL("DROP DATABASE {}").format(
                            sql.Identifier(scratch_db)
                        ))
            finally:
                source.close()


def _connect(settings: LabSettings, database: str):
    return psycopg.connect(
        host=settings.db_host, port=settings.db_port, dbname=database,
        user="networkpulse_staging", password=settings.db_password,
        connect_timeout=8, autocommit=True,
    )


def require_ci(project: str, confirmed: bool, workdir: Path) -> None:
    # Reuse validated Docker ownership and local runner guard from Stage B.
    require_disposable_ci(project, confirmed)
    if os.getenv("NETWORKPULSE_STAGE_B_DR_CONFIRM") != CONSENT:
        raise ValueError("Additional encrypted DR consent required")
    owned_container(project, "db")
    owned_container(project, "redis")
    root = Path(os.environ.get("RUNNER_TEMP", "/nonexistent")).resolve()
    if (not workdir.is_dir() or workdir.is_symlink()
            or workdir.resolve().parent != root
            or stat.S_IMODE(workdir.stat().st_mode) != 0o700
            or any(workdir.iterdir())):
        raise ValueError("Encrypted DR requires an empty mode-0700 CI scratch directory")
    _key()


def run_drill(workdir: Path) -> dict:
    key = _key()
    settings = LabSettings.from_env()
    pg, cache = settings.connect()
    harness = SyntheticIntegrityHarness(pg, cache, max_backlog=250)
    scratch_db = "networkpulse_stageb_drill_" + uuid.uuid4().hex[:12]
    encrypted = workdir / "synthetic-stage-b.pgcustom.aesgcm"
    manifest_file = workdir / "synthetic-stage-b.manifest.json"
    try:
        report = harness.run(180)
        if not report["reconciled"] or report["db_unique"] != 180:
            raise RuntimeError("Source synthetic database reconciliation failed")
        rows = _read_rows(pg, harness.run_id)
        with pg.cursor() as cur:
            cur.execute(f"SELECT count(*) FROM {TABLE}")
            if cur.fetchone()[0] != len(rows):
                raise RuntimeError("Non-isolated data present; refusing backup")
        scope = {"source_database": DATABASE_NAME, "table": TABLE_ID,
                 "run_id": harness.run_id, "row_count": len(rows),
                 "fingerprint": _fingerprint(rows)}
        backup = _backup(settings, encrypted, manifest_file, scope, key)
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))

        # Negative paths must be executed and verified BEFORE creating restore DB.
        wrong_key_rejected = False
        try:
            _decrypt_verified(encrypted, workdir / "wrong-key.tmp", manifest, os.urandom(32))
        except ValueError:
            wrong_key_rejected = True
        if not wrong_key_rejected:
            raise RuntimeError("Wrong-key authentication was not rejected")
        corrupted = workdir / "tampered.aesgcm"
        with encrypted.open("rb") as source, _reserve(corrupted) as out:
            payload = bytearray(source.read())
            payload[len(MAGIC) + 13] ^= 0x01
            out.write(payload)
        tamper_rejected = False
        try:
            _decrypt_verified(corrupted, workdir / "tampered.tmp", manifest, key)
        except ValueError:
            tamper_rejected = True
        finally:
            corrupted.unlink(missing_ok=True)
        if not tamper_rejected:
            raise RuntimeError("Tampered ciphertext was not rejected")
        restore = _restore(settings, scratch_db, encrypted, manifest, key, workdir)
        return {
            "status": "passed", "scope": "disposable_ci_synthetic_nonml_encrypted_dr",
            "operational_acceptance": "NOT_CLAIMED",
            "backup_algorithm": "AES-256-GCM", "encryption_authenticated": True,
            "wrong_key_rejected": wrong_key_rejected, "tamper_rejected": tamper_rejected,
            "source_unique": len(rows), "source_reconciled": report["reconciled"],
            "archive_sha256": manifest["archive_sha256"],
            "encrypted_bytes": manifest["encrypted_bytes"],
            "backup_seconds": backup["backup_seconds"], **restore,
            "rpo_rto_certification": "NOT_CLAIMED",
            "offsite_retention": "NOT_TESTED",
        }
    finally:
        harness.cleanup_synthetic_run()
        pg.close()
        cache.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-disposable-ci", action="store_true")
    parser.add_argument("--project", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    require_ci(args.project, args.confirm_disposable_ci, args.output_dir)
    if args.report.exists() or args.report.is_symlink():
        raise FileExistsError("Refusing to overwrite DR evidence")
    try:
        result = run_drill(args.output_dir)
    except Exception as exc:
        result = {"status": "failed", "scope": "disposable_ci_synthetic_nonml_encrypted_dr",
                  "failure_class": type(exc).__name__,
                  "operational_acceptance": "NOT_CLAIMED"}
    with _reserve(args.report) as stream:
        stream.write(json.dumps(result, sort_keys=True, indent=2).encode("utf-8"))
    print(json.dumps({"status": result["status"], "scope": result["scope"]}))
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
