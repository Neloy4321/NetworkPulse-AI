"""Download and verify authorized source archives for native UNSW->TON evaluation."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import time
from contextlib import redirect_stderr
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from networkpulse.evaluation.unsw_to_toniot import TON_SHA, UNSW_SHA

TRANSIENT_MARKERS = (
    "too many users",
    "quota",
    "rate limit",
    "try accessing the file again later",
    "failed to retrieve file url",
    "temporarily unavailable",
)


@dataclass(frozen=True)
class AuthorizedArchive:
    name: str
    output_path: Path
    file_id: str
    expected_bytes: int
    expected_sha256: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_transient(message: str) -> bool:
    lowered = (message or "").lower()
    return any(marker in lowered for marker in TRANSIENT_MARKERS)


def _verify(path: Path, expected_bytes: int, expected_sha256: str) -> str | None:
    size = path.stat().st_size
    if size != expected_bytes:
        return f"size mismatch: expected {expected_bytes} bytes, got {size}"
    actual_sha = _sha256(path)
    if actual_sha != expected_sha256:
        return f"sha256 mismatch: expected {expected_sha256}, got {actual_sha}"
    return None


def _attempt_download(
    archive: AuthorizedArchive,
    downloader: Callable[..., object],
) -> tuple[object | None, str, Exception | None]:
    stderr = io.StringIO()
    raised = None
    result = None
    with redirect_stderr(stderr):
        try:
            result = downloader(
                id=archive.file_id,
                output=str(archive.output_path),
                quiet=True,
                fuzzy=True,
                resume=True,
            )
        except Exception as exc:  # pragma: no cover - exercised via tests
            raised = exc
    return result, stderr.getvalue(), raised


def fetch_authorized_archives(
    archives: tuple[AuthorizedArchive, ...],
    downloader: Callable[..., object],
    attempts: int = 3,
    retry_sleep_seconds: int = 20,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> tuple[bool, dict]:
    unavailable: list[dict] = []
    for archive in archives:
        last_error = "unknown failure"
        for attempt in range(1, attempts + 1):
            result, stderr_text, raised = _attempt_download(archive, downloader)
            path = archive.output_path
            file_exists = path.exists()
            size = path.stat().st_size if file_exists else 0
            combined_error = " ".join(
                [x for x in (str(raised) if raised else "", stderr_text.strip()) if x]
            ).strip()

            if file_exists:
                verification_error = _verify(path, archive.expected_bytes, archive.expected_sha256)
                if verification_error is None:
                    break
                last_error = verification_error
                if size > archive.expected_bytes or size == archive.expected_bytes:
                    path.unlink(missing_ok=True)
            else:
                verification_error = None

            partial = file_exists and size < archive.expected_bytes
            transient = _is_transient(combined_error) if combined_error else False
            if not combined_error and not result and not partial:
                combined_error = "Authorized source ZIP unavailable; no claim"
            if combined_error:
                last_error = combined_error

            retryable = partial or transient or verification_error is not None
            if not retryable:
                unavailable.append({"file": archive.name, "error": last_error})
                break
            if attempt < attempts:
                sleep_fn(retry_sleep_seconds)
        else:
            unavailable.append({"file": archive.name, "error": last_error})
            continue
        if unavailable and unavailable[-1].get("file") == archive.name:
            continue

    if unavailable:
        return False, {
            "status": "unavailable-source",
            "reason": "authorized dataset unavailable or failed integrity verification",
            "unavailable_sources": unavailable,
        }
    return True, {"status": "ready"}


def _archives() -> tuple[AuthorizedArchive, ...]:
    return (
        AuthorizedArchive(
            name="unsw-source.zip",
            output_path=Path("unsw-source.zip"),
            file_id="16eIgENKYpiLwJNHZWRrYdPfGj6AOOtkT",
            expected_bytes=586382286,
            expected_sha256=UNSW_SHA,
        ),
        AuthorizedArchive(
            name="ton-source.zip",
            output_path=Path("ton-source.zip"),
            file_id="1rkNwQzrkpcnmtM8G5a-O7dAtr-y_9wFy",
            expected_bytes=3372478580,
            expected_sha256=TON_SHA,
        ),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--status-report", required=True)
    parser.add_argument("--github-output", default=os.environ.get("GITHUB_OUTPUT"))
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--retry-sleep-seconds", type=int, default=20)
    args = parser.parse_args()

    if not args.github_output:
        raise ValueError("github output destination is required")

    import gdown

    ready, report = fetch_authorized_archives(
        archives=_archives(),
        downloader=gdown.download,
        attempts=args.attempts,
        retry_sleep_seconds=args.retry_sleep_seconds,
    )
    if not ready:
        report_path = Path(args.status_report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    with Path(args.github_output).open("a", encoding="utf-8") as handle:
        handle.write(f"ready={'true' if ready else 'false'}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
