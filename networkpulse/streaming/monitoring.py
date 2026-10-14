"""Redis consumer-state snapshot, without exposing flow metadata."""

from __future__ import annotations

from networkpulse.streaming.redis_streams import DLQ, GROUP, STREAM


def stream_snapshot(client, *, stream: str = STREAM, group: str = GROUP,
                    dead_letter: str = DLQ) -> dict:
    depth = int(client.xlen(stream))
    dlq_depth = int(client.xlen(dead_letter))
    result = {
        "stream_depth": depth, "dead_letter_depth": dlq_depth,
        "pending": 0, "lag": None, "consumers": 0, "group_exists": False,
        "oldest_age_seconds": 0.0 if depth == 0 else None,
    }
    if not client.exists(stream):
        return result
    if depth:
        # Redis-generated IDs and Redis TIME share the same clock. This is
        # queue residence time, not network capture-to-alert latency.
        oldest = client.xrange(stream, min="-", max="+", count=1)
        if not oldest:
            raise RuntimeError("Redis stream length/entry inconsistency")
        seconds, micros = client.time()
        server_ms = int(seconds) * 1000 + int(micros) // 1000
        enqueued_ms = int(str(oldest[0][0]).split("-", 1)[0])
        result["oldest_age_seconds"] = round(
            max(0.0, (server_ms - enqueued_ms) / 1000), 3
        )
    for info in client.xinfo_groups(stream):
        if info["name"] == group:
            result["group_exists"] = True
            result["pending"] = int(info["pending"])
            result["consumers"] = int(info["consumers"])
            result["lag"] = None if info.get("lag") is None else int(info["lag"])
            break
    return result
