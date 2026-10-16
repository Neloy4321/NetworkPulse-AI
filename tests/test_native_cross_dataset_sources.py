from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from networkpulse.evaluation.native_cross_dataset_sources import (
    AuthorizedArchive,
    fetch_authorized_archives,
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _archive(tmp_path: Path, name: str, data: bytes) -> AuthorizedArchive:
    return AuthorizedArchive(
        name=name,
        output_path=tmp_path / name,
        file_id=f"id-{name}",
        expected_bytes=len(data),
        expected_sha256=_sha(data),
    )


def test_successful_download_and_verification(tmp_path: Path):
    payload = b"abc" * 400
    archive = _archive(tmp_path, "source.zip", payload)

    def downloader(**kwargs):
        Path(kwargs["output"]).write_bytes(payload)
        return kwargs["output"]

    ready, report = fetch_authorized_archives((archive,), downloader, attempts=2, sleep_fn=lambda *_: None)
    assert ready is True
    assert report["status"] == "ready"


def test_quota_failure_detected_when_download_returns_none_and_writes_stderr(tmp_path: Path, capsys):
    payload = b"abc" * 300
    archive = _archive(tmp_path, "source.zip", payload)

    def downloader(**kwargs):
        partial = payload[:100]
        with Path(kwargs["output"]).open("ab") as handle:
            handle.write(partial)
        print("Too many users have viewed or downloaded this file recently.", file=__import__("sys").stderr)
        return None

    ready, report = fetch_authorized_archives((archive,), downloader, attempts=1, sleep_fn=lambda *_: None)
    _ = capsys.readouterr()
    assert ready is False
    assert report["status"] == "unavailable-source"
    assert report["unavailable_sources"][0]["file"] == "source.zip"


def test_quota_failure_none_stderr_without_partial_file(tmp_path: Path):
    payload = b"abc" * 300
    archive = _archive(tmp_path, "source.zip", payload)

    def downloader(**kwargs):
        _ = kwargs
        print("Too many users have viewed or downloaded this file recently.", file=__import__("sys").stderr)
        return None

    ready, report = fetch_authorized_archives((archive,), downloader, attempts=1, sleep_fn=lambda *_: None)
    assert ready is False
    assert report["status"] == "unavailable-source"
    assert "too many users" in report["unavailable_sources"][0]["error"].lower()


def test_retry_recovery_preserves_partial_download_for_resume(tmp_path: Path):
    payload = b"0123456789" * 200
    archive = _archive(tmp_path, "source.zip", payload)
    state = {"attempt": 0, "saw_partial_on_retry": False}

    def downloader(**kwargs):
        output = Path(kwargs["output"])
        state["attempt"] += 1
        if state["attempt"] == 1:
            output.write_bytes(payload[:500])
            print("quota exceeded", file=__import__("sys").stderr)
            return None
        state["saw_partial_on_retry"] = output.exists() and output.stat().st_size == 500
        with output.open("ab") as handle:
            handle.write(payload[500:])
        return kwargs["output"]

    ready, _ = fetch_authorized_archives((archive,), downloader, attempts=3, sleep_fn=lambda *_: None)
    assert ready is True
    assert state["saw_partial_on_retry"] is True


def test_non_retryable_error_fails_closed(tmp_path: Path):
    payload = b"x" * 10
    archive = _archive(tmp_path, "source.zip", payload)
    state = {"attempt": 0}

    def downloader(**kwargs):
        state["attempt"] += 1
        raise RuntimeError("403 forbidden")

    ready, report = fetch_authorized_archives((archive,), downloader, attempts=3, sleep_fn=lambda *_: None)
    assert ready is False
    assert state["attempt"] == 1
    assert "403 forbidden" in report["unavailable_sources"][0]["error"]


def test_non_retryable_error_with_partial_file_fails_promptly(tmp_path: Path):
    payload = b"x" * 128
    archive = _archive(tmp_path, "source.zip", payload)
    state = {"attempt": 0}

    def downloader(**kwargs):
        state["attempt"] += 1
        Path(kwargs["output"]).write_bytes(payload[:16])
        raise RuntimeError("403 Forbidden")

    ready, report = fetch_authorized_archives((archive,), downloader, attempts=3, sleep_fn=lambda *_: None)
    assert ready is False
    assert state["attempt"] == 1
    assert "403 forbidden" in report["unavailable_sources"][0]["error"].lower()


def test_generic_retrieval_error_with_partial_file_fails_promptly(tmp_path: Path):
    payload = b"x" * 1024
    archive = _archive(tmp_path, "source.zip", payload)
    state = {"attempt": 0}

    def downloader(**kwargs):
        state["attempt"] += 1
        Path(kwargs["output"]).write_bytes(payload[:200])
        raise RuntimeError("failed to retrieve file url")

    ready, report = fetch_authorized_archives((archive,), downloader, attempts=3, sleep_fn=lambda *_: None)
    assert ready is False
    assert state["attempt"] == 1
    assert "failed to retrieve file url" in report["unavailable_sources"][0]["error"].lower()


def test_checksum_mismatch_rejected(tmp_path: Path):
    payload = b"correct-data"
    archive = _archive(tmp_path, "source.zip", payload)
    wrong = b"wrong-data12"

    def downloader(**kwargs):
        Path(kwargs["output"]).write_bytes(wrong)
        return kwargs["output"]

    ready, report = fetch_authorized_archives((archive,), downloader, attempts=1, sleep_fn=lambda *_: None)
    assert ready is False
    assert "sha256 mismatch" in report["unavailable_sources"][0]["error"]
    assert not archive.output_path.exists()


def test_exhausted_retries_from_transient_exceptions(tmp_path: Path):
    payload = b"abc" * 3
    archive = _archive(tmp_path, "source.zip", payload)
    state = {"attempt": 0}

    def downloader(**kwargs):
        state["attempt"] += 1
        raise RuntimeError("Rate limit exceeded")

    ready, report = fetch_authorized_archives((archive,), downloader, attempts=3, sleep_fn=lambda *_: None)
    assert ready is False
    assert state["attempt"] == 3
    assert "Rate limit exceeded" in report["unavailable_sources"][0]["error"]


def test_partial_file_without_explicit_quota_message_is_retried(tmp_path: Path):
    payload = b"A" * 2048
    archive = _archive(tmp_path, "source.zip", payload)
    state = {"attempt": 0}

    def downloader(**kwargs):
        path = Path(kwargs["output"])
        state["attempt"] += 1
        if state["attempt"] == 1:
            path.write_bytes(payload[:300])
            return None
        with path.open("ab") as handle:
            handle.write(payload[300:])
        return kwargs["output"]

    ready, report = fetch_authorized_archives((archive,), downloader, attempts=2, sleep_fn=lambda *_: None)
    assert ready is True
    assert report["status"] == "ready"


def test_integrated_source_only_workflow_fails_on_missing_verified_evidence():
    # This integration intentionally leaves the independently failing TON
    # numerical-acceptance workflow on draft PR #25. Only the fully tested
    # fail-closed R2 research source-acquisition pipeline is promoted.
    workflow = Path(__file__).resolve().parents[1] / ".github/workflows/source-only-feature-audit.yml"
    content = workflow.read_text(encoding="utf-8")
    assert "private_r2_sources" in content
    assert "Fail when source-only audit is unavailable" in content
    assert "if: always()" in content
    assert "Source-only audit evidence unavailable: FAIL" in content
    assert "Invalid source-only audit status: FAIL" in content
    assert "Unexpected operational acceptance claim: FAIL" in content


def test_refuse_zero_attempts_without_marking_archives_ready(tmp_path: Path):
    payload = b"real-data"
    archive = _archive(tmp_path, "source.zip", payload)
    calls = []

    def downloader(**kwargs):
        calls.append(kwargs)
        return None

    with pytest.raises(ValueError, match="attempts must be at least 1"):
        fetch_authorized_archives((archive,), downloader, attempts=0)
    assert calls == []


def test_refuse_empty_authorized_archive_set():
    with pytest.raises(ValueError, match="at least one authorized archive"):
        fetch_authorized_archives((), lambda **_: None)


def test_refuse_negative_retry_delay(tmp_path: Path):
    archive = _archive(tmp_path, "source.zip", b"real-data")
    with pytest.raises(ValueError, match="retry_sleep_seconds cannot be negative"):
        fetch_authorized_archives((archive,), lambda **_: None, retry_sleep_seconds=-1)
