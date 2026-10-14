"""Loss-intolerant, checkpointed JSONL sensor-log collector.

Only a single owner may tail a source/checkpoint. POSIX rename rotation is
recovered from a retained inode in the same directory. Missing history and
copy-truncate are fail-closed: never silently skip unknown traffic.

Exactly-once publication is not claimed. An enqueue acknowledged by Redis
before checkpoint fsync can replay after a crash; downstream DB uniqueness
ensures exactly-once committed effects.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import stat
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from networkpulse.adapters import SkipRecord, parse

MAX_LINE_BYTES = 1_000_000
MAX_CHECKPOINT_BYTES = 4096
MAX_ROTATED_FILES = 4096


class ContinuityError(RuntimeError):
    """A sensor log may contain unprocessed data; operator action is required."""


def _identity(info: os.stat_result) -> list[int]:
    return [int(info.st_dev), int(info.st_ino)]


def _open_regular(path: Path):
    # Never follow a symlink to private or unexpected telemetry.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ContinuityError("Collector requires a regular file")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def _checkpoint(path: Path, state: dict) -> None:
    """Atomic, owner-only checkpoint; sync both data and directory entry."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, candidate = tempfile.mkstemp(prefix=".np-offset-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(state, stream, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(candidate, path)
        # fsync the rename itself; file-only fsync cannot persist the directory
        # entry across an abrupt power loss.
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(candidate):
            os.unlink(candidate)


def _read_checkpoint(path: Path) -> dict | None:
    try:
        with _open_regular(path) as stream:
            data = stream.read(MAX_CHECKPOINT_BYTES + 1)
    except FileNotFoundError:
        return None
    if len(data) > MAX_CHECKPOINT_BYTES:
        raise ContinuityError("Collector checkpoint exceeds size bound")
    try:
        record = json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise ContinuityError("Collector checkpoint is corrupt; refusing reset") from exc
    if not isinstance(record, dict):
        raise ContinuityError("Collector checkpoint is not a JSON object")
    identity = record.get("identity")
    offset = record.get("offset")
    if (not isinstance(identity, list) or len(identity) != 2
            or any(type(v) is not int or v < 0 for v in identity)
            or type(offset) is not int or offset < 0):
        raise ContinuityError("Collector checkpoint identity/offset is invalid")
    # Old offset-only checkpoints remain readable; upgraded checkpoints
    # verify a trailing byte fingerprint to detect copytruncate + regrowth.
    anchor_len = record.get("anchor_len", 0)
    anchor_hash = record.get("anchor_sha256")
    if (type(anchor_len) is not int or not 0 <= anchor_len <= min(offset, 128)
            or (anchor_len == 0 and anchor_hash is not None)
            or (anchor_len > 0 and (
                not isinstance(anchor_hash, str) or len(anchor_hash) != 64
                or any(c not in "0123456789abcdef" for c in anchor_hash)
            ))):
        raise ContinuityError("Collector checkpoint anchor is invalid")
    return {
        "identity": identity, "offset": offset,
        "anchor_len": anchor_len, "anchor_sha256": anchor_hash,
    }


class LogCollector:
    def __init__(self, source: Path, fmt: str, checkpoint: Path, enqueue):
        if fmt not in {"zeek", "suricata", "canonical"}:
            raise ValueError("unsupported collector log format")
        self.path = Path(source)
        self.fmt = fmt
        self.checkpoint = Path(checkpoint)
        self.enqueue = enqueue

    @contextmanager
    def _ownership(self):
        """Hold the exclusive checkpoint lease throughout follow(), not per row."""
        self.checkpoint.parent.mkdir(parents=True, exist_ok=True)
        lockpath = Path(str(self.checkpoint) + ".lock")
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(lockpath, flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ContinuityError("Collector lock must be a regular file")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ContinuityError(
                    "Collector checkpoint already owned by another process"
                ) from exc
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _rotated_inode(self, expected: list[int]) -> Path:
        """Locate a retained, uncompressed rename-rotated file by inode.

        No guess based on suffix or timestamp is safe. A deleted/compressed
        source means continuity cannot be established; refuse a silent reset.
        """
        try:
            with os.scandir(self.path.parent) as entries:
                for count, entry in enumerate(entries, 1):
                    if count > MAX_ROTATED_FILES:
                        raise ContinuityError(
                            "Rotation directory exceeds bounded scan capacity"
                        )
                    try:
                        if entry.is_file(follow_symlinks=False):
                            info = entry.stat(follow_symlinks=False)
                            if _identity(info) == expected:
                                return Path(entry.path)
                    except FileNotFoundError:
                        continue
        except OSError as exc:
            raise ContinuityError("Cannot inspect sensor rotation directory") from exc
        raise ContinuityError(
            "Previous sensor inode is unavailable after rotation; do not skip unread flows"
        )

    def _consume(self, path: Path, expected: list[int], offset: int,
                 limit: int, *, rotated: bool, anchor_len: int = 0,
                 anchor_sha256: str | None = None) -> tuple[int, int, int, bool]:
        published = skipped = 0
        with _open_regular(path) as source:
            info = os.fstat(source.fileno())
            if _identity(info) != expected:
                raise ContinuityError("Sensor file changed during acquisition")
            if info.st_size < offset:
                raise ContinuityError(
                    "Sensor log truncated before checkpoint; copytruncate is unsafe"
                )
            # Compare a sample of previously acknowledged bytes before
            # reading anything new. Size checks alone cannot detect logs
            # truncated and rapidly rewritten past their prior offset.
            source.seek(offset - min(offset, 128))
            tail = source.read(min(offset, 128))
            if (anchor_len and not hmac.compare_digest(
                    hashlib.sha256(tail[-anchor_len:]).hexdigest(),
                    anchor_sha256 or "",
            )):
                raise ContinuityError(
                    "Previously checkpointed sensor bytes were rewritten"
                )
            source.seek(offset)
            while published + skipped < limit:
                line_start = source.tell()
                line = source.readline(MAX_LINE_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_LINE_BYTES:
                    raise ContinuityError("Sensor record exceeds 1 MB limit")
                if not line.endswith(b"\n"):
                    if rotated:
                        raise ContinuityError(
                            "Rotated sensor log has an incomplete final record"
                        )
                    # Writer has not flushed a complete JSONL record yet.
                    break
                if not line.strip():
                    skipped += 1
                else:
                    try:
                        obj = json.loads(line)
                        if not isinstance(obj, dict):
                            raise ValueError("expected JSON object")
                        event = parse(obj, self.fmt)
                    except SkipRecord:
                        skipped += 1
                    except (ValueError, KeyError, TypeError, UnicodeError) as exc:
                        raise ContinuityError(
                            "Invalid sensor record; offset preserved for investigation"
                        ) from exc
                    else:
                        # Never advance the durable checkpoint until Redis XADD
                        # has returned successfully. A crash may cause replay.
                        self.enqueue(event.model_dump(mode="json"))
                        published += 1
                offset = source.tell()
                tail = (tail + line)[-128:]
                _checkpoint(self.checkpoint, {
                    "identity": expected, "offset": offset,
                    "anchor_len": len(tail),
                    "anchor_sha256": hashlib.sha256(tail).hexdigest()
                    if tail else None,
                })
                if offset <= line_start:
                    raise ContinuityError("Sensor read offset failed to advance")
            # If this file has already rotated, it must be fully drained before
            # moving to the active inode. No unknown partial final record.
            at_eof = source.tell() == os.fstat(source.fileno()).st_size
        return published, skipped, offset, at_eof

    def _poll_unlocked(self, *, max_rows: int) -> dict:
        if not 1 <= max_rows <= 1000:
            raise ValueError("max_rows must be between 1 and 1000")
        saved = _read_checkpoint(self.checkpoint)
        try:
            with _open_regular(self.path) as current:
                live = _identity(os.fstat(current.fileno()))
        except FileNotFoundError:
            live = None

        if saved is None and live is None:
            return {"published": 0, "skipped": 0, "available": False}
        if saved is None:
            saved = {"identity": live, "offset": 0}
            _checkpoint(self.checkpoint, saved)

        published = skipped = 0
        recovered = False
        if saved["identity"] != live:
            # Recovery must drain the previous inode FIRST. Otherwise a
            # rename during a burst permanently loses the unread tail.
            rotated = self._rotated_inode(saved["identity"])
            a, b, offset, done = self._consume(
                rotated, saved["identity"], saved["offset"], max_rows,
                rotated=True, anchor_len=saved.get("anchor_len", 0),
                anchor_sha256=saved.get("anchor_sha256"),
            )
            published += a
            skipped += b
            if not done or published + skipped >= max_rows:
                return {
                    "published": published, "skipped": skipped,
                    "available": live is not None, "offset": offset,
                    "rotation_recovered": False,
                }
            recovered = True
            if live is None:
                # No active file yet. Do not reassign checkpoint to an inode
                # that does not exist; poll again after the sensor reopens.
                return {
                    "published": published, "skipped": skipped,
                    "available": False, "offset": offset,
                    "rotation_recovered": True,
                }
            saved = {"identity": live, "offset": 0}
            _checkpoint(self.checkpoint, saved)
        if live is None:
            return {"published": 0, "skipped": 0, "available": False}
        a, b, offset, _ = self._consume(
            self.path, saved["identity"], saved["offset"],
            max_rows - published - skipped, rotated=False,
            anchor_len=saved.get("anchor_len", 0),
            anchor_sha256=saved.get("anchor_sha256"),
        )
        return {
            "published": published + a, "skipped": skipped + b,
            "available": True, "offset": offset,
            "rotation_recovered": recovered,
        }

    def poll_once(self, *, max_rows: int = 250) -> dict:
        with self._ownership():
            return self._poll_unlocked(max_rows=max_rows)

    def follow(self, *, interval: float = 1.0):
        if not 0.05 <= interval <= 60:
            raise ValueError("poll interval must be 0.05..60 seconds")
        with self._ownership():
            while True:
                self._poll_unlocked(max_rows=250)
                time.sleep(interval)
