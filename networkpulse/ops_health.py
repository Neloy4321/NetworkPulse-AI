"""Container worker heartbeat: freshness reflects a *completed successful cycle*.

The file is only a health signal, never operational evidence. A stalled process
becomes unhealthy, and an exception exits so Docker's restart policy can act.
"""
from __future__ import annotations

import argparse
import json
import os
import tempfile
import time
from pathlib import Path

ROLES = {"behavior", "mlops"}


def mark_success(path: Path, role: str) -> None:
    """Atomic replace; healthcheck never reads a half-written heartbeat."""
    if role not in ROLES:
        raise ValueError("unknown worker role")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".np-heartbeat-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump({"role": role, "success_at_epoch": time.time(),
                       "pid": os.getpid()}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def is_healthy(path: Path, role: str, *, max_age_seconds: int,
               now: float | None = None) -> bool:
    """Fail closed on missing, malformed, stale or future-dated success."""
    if role not in ROLES or not 60 <= max_age_seconds <= 3600:
        raise ValueError("invalid healthcheck configuration")
    try:
        record = json.loads(Path(path).read_text(encoding="utf-8"))
        stamp = record["success_at_epoch"]
        if type(stamp) not in {float, int} or record.get("role") != role:
            return False
        age = (time.time() if now is None else now) - stamp
        return -5 <= age <= max_age_seconds
    except (OSError, ValueError, TypeError, KeyError, OverflowError, AttributeError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Worker successful-cycle health")
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument("--role", choices=sorted(ROLES), required=True)
    parser.add_argument("--max-age-seconds", type=int, required=True)
    args = parser.parse_args()
    return 0 if is_healthy(args.path, args.role,
                            max_age_seconds=args.max_age_seconds) else 1


if __name__ == "__main__":
    raise SystemExit(main())
