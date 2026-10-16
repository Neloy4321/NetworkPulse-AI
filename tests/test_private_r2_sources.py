"""Fail-closed tests for private R2 native research source acquisition."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from networkpulse.evaluation.native_cross_dataset_sources import AuthorizedArchive
from networkpulse.evaluation.private_r2_sources import (
    _is_transient, _safe_error, fetch_r2_archives, stream_verified_object,
)


class FakeBody:
    def __init__(self, payload: bytes, *, fail: bool = False):
        self.payload = payload
        self.fail = fail
        self.closed = False

    def iter_chunks(self, chunk_size):
        yield self.payload[:3]
        if self.fail:
            raise RuntimeError("download interrupted; never expose credentials")
        yield self.payload[3:]

    def close(self):
        self.closed = True


class FakeClient:
    def __init__(self, payload: bytes, *, reported_bytes: int | None = None, fail=False):
        self.payload = payload
        self.reported_bytes = len(payload) if reported_bytes is None else reported_bytes
        self.fail = fail
        self.calls = []
        self.body = None

    def get_object(self, **kwargs):
        self.calls.append(kwargs)
        self.body = FakeBody(self.payload, fail=self.fail)
        return {"Body": self.body, "ContentLength": self.reported_bytes}


def archive(tmp_path: Path, payload: bytes, *, expected_sha: str | None = None):
    return AuthorizedArchive(
        name="unsw-source.zip",
        output_path=tmp_path / "unsw-source.zip",
        file_id="irrelevant-google-drive-id",
        expected_bytes=len(payload),
        expected_sha256=expected_sha or hashlib.sha256(payload).hexdigest(),
    )


def test_real_s3_key_size_and_sha_verified_before_publish(tmp_path):
    data = b"zip-bytes-authentic"
    src = archive(tmp_path, data)
    client = FakeClient(data)
    stream_verified_object(client, src)
    assert src.output_path.read_bytes() == data
    assert client.calls == [{
        "Bucket": "networkpulse-ml-datasets",
        "Key": "OneDrive_2_9-14-2026.zip",
    }]
    assert client.body.closed
    assert not list(tmp_path.glob("*.partial"))


def test_sha_mismatch_fails_closed_and_cleans_partial(tmp_path):
    data = b"zip-bytes"
    src = archive(tmp_path, data, expected_sha="0" * 64)
    ready, report = fetch_r2_archives(FakeClient(data), (src,))
    assert ready is False
    assert report["status"] == "unavailable-source"
    assert "sha256 mismatch" in report["unavailable_sources"][0]["error"]
    assert not src.output_path.exists()
    assert not list(tmp_path.glob("*.partial"))


def test_size_mismatch_fails_closed(tmp_path):
    data = b"zip-bytes"
    src = archive(tmp_path, data)
    ready, report = fetch_r2_archives(FakeClient(data, reported_bytes=1), (src,))
    assert not ready
    assert "size mismatch" in report["unavailable_sources"][0]["error"]
    assert not src.output_path.exists()
    assert not list(tmp_path.glob("*.partial"))


def test_stream_interrupted_fails_closed_and_sanitizes_errors(tmp_path):
    data = b"zip-bytes"
    src = archive(tmp_path, data)
    client = FakeClient(data, fail=True)
    ready, report = fetch_r2_archives(client, (src,))
    assert not ready
    assert report["unavailable_sources"][0]["error"] == "RuntimeError"
    assert "credentials" not in str(report)
    assert not src.output_path.exists()
    assert not list(tmp_path.glob("*.partial"))
    assert client.body.closed


def test_successful_fetch_declares_ready_only_after_verification(tmp_path):
    data = b"zip-bytes"
    src = archive(tmp_path, data)
    ready, report = fetch_r2_archives(FakeClient(data), (src,))
    assert ready
    assert report == {"status": "ready", "source": "private-r2", "verified_count": 1}


def test_unrecognized_archive_cannot_select_arbitrary_s3_key(tmp_path):
    src = archive(tmp_path, b"bytes")
    src = AuthorizedArchive(
        name="unapproved.zip", output_path=src.output_path,
        file_id="ignored", expected_bytes=5, expected_sha256="0" * 64,
    )
    ready, report = fetch_r2_archives(FakeClient(b"bytes"), (src,))
    assert not ready
    assert report["unavailable_sources"][0]["error"] == "unapproved source archive"


@pytest.mark.parametrize("count", [0, -1])
def test_invalid_attempts_cannot_mark_ready(tmp_path, count):
    with pytest.raises(ValueError, match="attempts must be at least 1"):
        fetch_r2_archives(FakeClient(b"x"), (archive(tmp_path, b"x"),), attempts=count)


def test_missing_archive_set_cannot_mark_ready():
    with pytest.raises(ValueError, match="at least one authorized archive"):
        fetch_r2_archives(FakeClient(b"x"), ())


def test_transient_code_and_safe_error_without_sensitive_detail():
    class TransientError(Exception):
        response = {"Error": {"Code": "SlowDown", "Message": "secret-access-key"}}
    error = TransientError("secret-access-key")
    assert _is_transient(error)
    assert _safe_error(error) == "TransientError: SlowDown"


def test_workflow_uses_private_r2_and_fails_on_numeric_quality_gate():
    workflow = (Path(__file__).resolve().parents[1] /
                ".github/workflows/native-cross-dataset.yml").read_text(encoding="utf-8")
    assert "networkpulse.evaluation.private_r2_sources" in workflow
    assert "secrets.R2_ACCESS_KEY_ID" in workflow
    assert "secrets.R2_SECRET_ACCESS_KEY" in workflow
    assert "secrets.R2_ENDPOINT" in workflow
    assert "Fail if predeclared research numerical gate fails" in workflow
    assert 'if status != "passed":' in workflow
    assert "Predeclared numeric quality gate FAILED" in workflow
