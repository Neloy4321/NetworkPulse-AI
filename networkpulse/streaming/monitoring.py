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
    }
    if not client.exists(stream):
        return result
    for info in client.xinfo_groups(stream):
        if info["name"] == group:
            result["group_exists"] = True
            result["pending"] = int(info["pending"])
            result["consumers"] = int(info["consumers"])
            result["lag"] = None if info.get("lag") is None else int(info["lag"])
            break
    return result
