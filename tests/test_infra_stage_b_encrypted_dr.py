"""Non-ML encrypted DR: independent crypto and destructive-guard unit tests."""
from __future__ import annotations

import io
import json
import os
import stat

import pytest

from networkpulse import infra_stage_b_encrypted_dr as dr


def _manifest(path, scope):
    return {"format": dr.FORMAT, "scope": scope,
            "archive_name": path.name, "archive_sha256": dr._sha(path)}


def _fixture(tmp_path):
    key = os.urandom(32)
    scope = {"source_database": dr.DATABASE_NAME, "table": dr.TABLE_ID,
             "run_id": "a" * 32, "row_count": 1,
             "fingerprint": "b" * 64}
    target = tmp_path / "test.aesgcm"
    payload = b"PostgreSQL custom format binary test payload" * 50
    dr._encrypted_stream(io.BytesIO(payload), target, key, dr._json_bytes(scope))
    return key, scope, target, payload


def test_stream_encryption_authentication_and_permissions(tmp_path):
    key, scope, archive, payload = _fixture(tmp_path)
    destination = tmp_path / "verified.pgcustom"
    dr._decrypt_verified(archive, destination, _manifest(archive, scope), key)
    assert destination.read_bytes() == payload
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert archive.read_bytes() != payload
    assert b"PostgreSQL custom format binary" not in archive.read_bytes()
    with pytest.raises(FileExistsError):
        dr._encrypted_stream(io.BytesIO(payload), archive, key, dr._json_bytes(scope))


def test_wrong_key_rejects_and_cleans_unauthenticated_plaintext(tmp_path):
    key, scope, archive, _ = _fixture(tmp_path)
    decrypted = tmp_path / "unauthenticated.pgcustom"
    with pytest.raises(ValueError, match="authentication failed"):
        dr._decrypt_verified(archive, decrypted, _manifest(archive, scope),
                             os.urandom(32))
    assert not decrypted.exists()


def test_manifest_scope_tamper_fails_cryptographic_aad(tmp_path):
    key, scope, archive, _ = _fixture(tmp_path)
    tampered_scope = {**scope, "row_count": 2}
    decrypted = tmp_path / "aad-attack.pgcustom"
    with pytest.raises(ValueError, match="authentication failed"):
        dr._decrypt_verified(archive, decrypted, _manifest(archive, tampered_scope), key)
    assert not decrypted.exists()


def test_ciphertext_modification_rejected_even_if_checksum_updated(tmp_path):
    key, scope, archive, _ = _fixture(tmp_path)
    content = bytearray(archive.read_bytes())
    content[len(dr.MAGIC) + 12 + 5] ^= 1
    archive.write_bytes(content)
    decrypted = tmp_path / "modified.pgcustom"
    with pytest.raises(ValueError, match="authentication failed"):
        dr._decrypt_verified(archive, decrypted, _manifest(archive, scope), key)
    assert not decrypted.exists()


def test_truncation_and_symlink_refusal(tmp_path):
    key, scope, archive, _ = _fixture(tmp_path)
    archive.write_bytes(dr.MAGIC + b"x" * 6)
    with pytest.raises(ValueError, match="Truncated"):
        dr._decrypt_verified(archive, tmp_path / "short.pgcustom",
                             _manifest(archive, scope), key)
    assert not (tmp_path / "short.pgcustom").exists()
    link = tmp_path / "link.aesgcm"
    link.symlink_to(archive)
    with pytest.raises(FileExistsError):
        dr._encrypted_stream(io.BytesIO(b"abc"), link, key, dr._json_bytes(scope))


def test_key_missing_and_invalid(monkeypatch):
    monkeypatch.delenv(dr.KEY_ENV, raising=False)
    with pytest.raises(ValueError, match="64 hex"):
        dr._key()
    monkeypatch.setenv(dr.KEY_ENV, "x" * 64)
    with pytest.raises(ValueError, match="64 hex"):
        dr._key()
    monkeypatch.setenv(dr.KEY_ENV, "a" * 64)
    assert dr._key() == bytes.fromhex("a" * 64)


def test_restore_refuses_wrong_target_without_creating_database(monkeypatch, tmp_path):
    key, scope, archive, _ = _fixture(tmp_path)
    manifest = _manifest(archive, scope)

    def unexpected_connection(*args, **kwargs):
        raise AssertionError("No DB connections allowed for unsafe target")

    monkeypatch.setattr(dr, "_connect", unexpected_connection)
    with pytest.raises(ValueError, match="distinct random CI database"):
        dr._restore(None, "networkpulse_staging_infra", archive, manifest, key, tmp_path)
    assert not (tmp_path / "authenticated-transient.pgcustom").exists()


def test_authentication_precedes_restore_database_creation(monkeypatch, tmp_path):
    key, scope, archive, _ = _fixture(tmp_path)
    manifest = _manifest(archive, scope)
    manifest["scope"] = {**scope, "source_database": "production"}
    monkeypatch.setattr(dr, "_connect", lambda *_: pytest.fail("DB touched"))
    with pytest.raises(ValueError, match="scope"):
        dr._restore(None, "networkpulse_stageb_drill_" + "c" * 12, archive,
                    manifest, key, tmp_path)
    assert not (tmp_path / "authenticated-transient.pgcustom").exists()


def test_crypto_scope_fingerprint_deterministic():
    rows = [("test:000000", 0, "a" * 64)]
    assert dr._fingerprint(rows) == dr._fingerprint(list(rows))
    assert dr._fingerprint(rows) != dr._fingerprint([])


def test_no_prod_recovery_or_ml_code_path():
    from pathlib import Path
    code = Path(dr.__file__).read_text(encoding="utf-8")
    assert "from networkpulse.detector import" not in code
    assert "from networkpulse.recovery import" not in code
    assert "pg_restore" in code
    assert "NOT_CLAIMED" in code
