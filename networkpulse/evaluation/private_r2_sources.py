"""Read only SHA-pinned UNSW and TON ZIPs from a private Cloudflare R2 bucket.

A successful HTTP response never counts as a verified source. Byte length and
SHA-256 are checked while streaming before an archive is made available to ML.
Only aggregated evaluation reports, never source ZIPs, may be CI artifacts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Callable, Mapping

from networkpulse.evaluation.native_cross_dataset_sources import AuthorizedArchive, _archives

BUCKET = "networkpulse-ml-datasets"
R2_OBJECT_KEYS = {
    "unsw-source.zip": "OneDrive_2_9-14-2026.zip",
    "ton-source.zip": "OneDrive_1_9-14-2026.zip",
}
CHUNK_BYTES = 8 * 1024 * 1024
TRANSIENT_ERROR_CODES = {
    "RequestTimeout", "RequestTimeoutException", "SlowDown", "Throttling",
    "ThrottlingException", "InternalError", "ServiceUnavailable",
    "500", "502", "503", "504",
}
TRANSIENT_EXCEPTION_NAMES = {
    "ReadTimeoutError", "ConnectTimeoutError", "EndpointConnectionError",
    "ConnectionClosedError",
}


class SourceIntegrityError(ValueError):
    """A source cannot be used, even if the provider delivered an object."""


def _safe_error(exc: Exception) -> str:
    """Never record raw third-party exception strings or credentials in artifacts."""
    if isinstance(exc, SourceIntegrityError):
        return str(exc)
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
        if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", code):
            return f"{type(exc).__name__}: {code}"
    return type(exc).__name__


def _is_transient(exc: Exception) -> bool:
    if isinstance(exc, SourceIntegrityError):
        return False
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
        if code in TRANSIENT_ERROR_CODES:
            return True
    return type(exc).__name__ in TRANSIENT_EXCEPTION_NAMES


def stream_verified_object(
    client: object,
    archive: AuthorizedArchive,
    *,
    bucket: str = BUCKET,
    object_keys: Mapping[str, str] = R2_OBJECT_KEYS,
) -> None:
    """Download to a disposable .partial file; publish only after full verification."""
    key = object_keys.get(archive.name)
    if not key:
        raise SourceIntegrityError("unapproved source archive")
    target = archive.output_path
    target.parent.mkdir(parents=True, exist_ok=True)
    partial: Path | None = None
    body = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{target.name}.", suffix=".partial",
            dir=target.parent, delete=False,
        ) as sink:
            partial = Path(sink.name)
            response = client.get_object(Bucket=bucket, Key=key)
            if response.get("ContentLength") != archive.expected_bytes:
                raise SourceIntegrityError("size mismatch with SHA-pinned approved archive")
            body = response["Body"]
            actual_bytes = 0
            sha256 = hashlib.sha256()
            for chunk in body.iter_chunks(chunk_size=CHUNK_BYTES):
                if not chunk:
                    continue
                actual_bytes += len(chunk)
                if actual_bytes > archive.expected_bytes:
                    raise SourceIntegrityError("source object exceeds approved byte count")
                sha256.update(chunk)
                sink.write(chunk)
            if actual_bytes != archive.expected_bytes:
                raise SourceIntegrityError("source object truncated during transfer")
            if sha256.hexdigest() != archive.expected_sha256:
                raise SourceIntegrityError("sha256 mismatch with approved source")
        os.replace(partial, target)
    finally:
        if body is not None:
            try:
                body.close()
            except Exception:
                pass  # A failed stream remains failed; never mask its original exception.
        if partial is not None:
            partial.unlink(missing_ok=True)


def fetch_r2_archives(
    client: object,
    archives: tuple[AuthorizedArchive, ...],
    *,
    attempts: int = 3,
    retry_delay_seconds: float = 10,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> tuple[bool, dict]:
    if not archives:
        raise ValueError("at least one authorized archive is required")
    if attempts < 1:
        raise ValueError("attempts must be at least 1")
    if retry_delay_seconds < 0:
        raise ValueError("retry delay cannot be negative")
    for archive in archives:
        for attempt in range(1, attempts + 1):
            try:
                stream_verified_object(client, archive)
                break
            except Exception as exc:
                if attempt == attempts or not _is_transient(exc):
                    return False, {
                        "status": "unavailable-source",
                        "reason": "private R2 object unavailable or failed approved byte/SHA-256 checks",
                        "unavailable_sources": [
                            {"file": archive.name, "error": _safe_error(exc)}
                        ],
                    }
                sleep_fn(retry_delay_seconds)
    return True, {"status": "ready", "source": "private-r2", "verified_count": len(archives)}


def _configured_client():
    """Require the intended Cloudflare S3 endpoint, never an arbitrary credential sink."""
    endpoint = os.environ.get("R2_ENDPOINT", "")
    if not re.fullmatch(
        r"https://[0-9a-fA-F]{32}\.r2\.cloudflarestorage\.com/?", endpoint
    ):
        raise ValueError("missing or invalid Cloudflare R2 endpoint")
    if not os.environ.get("AWS_ACCESS_KEY_ID") or not os.environ.get("AWS_SECRET_ACCESS_KEY"):
        raise ValueError("private R2 credentials are missing")
    import boto3
    from botocore.config import Config

    return boto3.client(
        "s3",
        endpoint_url=endpoint.rstrip("/"),
        region_name="auto",
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            retries={"mode": "standard", "max_attempts": 4},
            connect_timeout=30,
            read_timeout=120,
        ),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--status-report", required=True)
    parser.add_argument("--github-output", default=os.environ.get("GITHUB_OUTPUT"))
    args = parser.parse_args(argv)
    if not args.github_output:
        parser.error("github output destination is required")

    try:
        client = _configured_client()
        ready, report = fetch_r2_archives(client, _archives())
    except Exception as exc:
        ready = False
        report = {
            "status": "unavailable-source",
            "reason": "private R2 configuration or source fetch failed",
            "unavailable_sources": [{"file": "private-r2", "error": _safe_error(exc)}],
        }

    if not ready:
        report_path = Path(args.status_report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    with Path(args.github_output).open("a", encoding="utf-8") as output:
        output.write(f"ready={'true' if ready else 'false'}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
