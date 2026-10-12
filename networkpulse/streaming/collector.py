"""File-tail collector with atomic file-offset checkpoints.

Each source log is watched by one collector instance. A crash between XADD and
checkpoint may replay a record; database idempotency absorbs the duplicate.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from networkpulse.adapters import parse, SkipRecord


def _checkpoint(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".pending")
    with temp.open("w", encoding="utf-8") as stream:
        json.dump(state, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(path)


class LogCollector:
    def __init__(self, source: Path, fmt: str, checkpoint: Path, enqueue):
        if fmt not in {"zeek", "suricata", "canonical"}:
            raise ValueError("unsupported collector log format")
        self.path = source
        self.fmt = fmt
        self.checkpoint = checkpoint
        self.enqueue = enqueue

    def poll_once(self, *, max_rows: int = 250) -> dict:
        state = json.loads(self.checkpoint.read_text()) if self.checkpoint.exists() else {}
        if not self.path.exists():
            return {"published": 0, "skipped": 0, "available": False}
        stat = self.path.stat()
        identity = (stat.st_dev, stat.st_ino)
        # Detect rotation or truncation. On Windows inode behavior is filesystem-dependent.
        if state.get("identity") != list(identity) or stat.st_size < state.get("offset", 0):
            state = {"identity": list(identity), "offset": 0}
        published = skipped = 0
        with self.path.open("rb") as stream:
            stream.seek(state["offset"])
            while published + skipped < max_rows:
                line = stream.readline(1_000_001)
                if not line:
                    break
                if not line.endswith(b"\n"):
                    # Incomplete log line: do not move checkpoint yet.
                    break
                if len(line) > 1_000_000:
                    raise ValueError("log line too large")
                if not line.strip():
                    skipped += 1
                else:
                    try:
                        value = json.loads(line)
                        event = parse(value, self.fmt)
                    except SkipRecord:
                        skipped += 1
                    except Exception as exc:
                        # Malformed records stop the collector, not silently discarded.
                        raise ValueError(f"invalid log record near byte {state['offset']}") from exc
                    else:
                        self.enqueue(event.model_dump(mode="json"))
                        published += 1
                state["offset"] = stream.tell()
                _checkpoint(self.checkpoint, state)
        return {"published": published, "skipped": skipped, "available": True, "offset": state["offset"]}

    def follow(self, *, interval: float = 1.0):
        while True:
            self.poll_once()
            time.sleep(interval)
