"""Leakage-aware, payload-free feature extraction for flow telemetry."""

from __future__ import annotations

import math

from networkpulse.schemas import FlowEvent

FEATURE_VERSION = 1


def event_features(event: FlowEvent) -> dict[str, float | str]:
    total_bytes = event.orig_bytes + event.resp_bytes
    total_pkts = event.orig_pkts + event.resp_pkts
    return {
        "log_duration": math.log1p(event.duration),
        "log_orig_bytes": math.log1p(event.orig_bytes),
        "log_resp_bytes": math.log1p(event.resp_bytes),
        "log_orig_pkts": math.log1p(event.orig_pkts),
        "log_resp_pkts": math.log1p(event.resp_pkts),
        "log_bytes_per_second": math.log1p(min(1e12, total_bytes / max(0.01, event.duration))),
        "log_bytes_per_packet": math.log1p(total_bytes / max(1, total_pkts)),
        "response_fraction": event.resp_bytes / max(1, total_bytes),
        "dst_port": float(event.dst_port),
        "dst_is_well_known": float(event.dst_port < 1024),
        "proto=" + event.proto: 1.0,
        "state=" + event.conn_state: 1.0,
    }


def explain(event: FlowEvent) -> list[str]:
    """Transparent heuristic evidence; *not* SHAP or a causal explanation of IF."""
    why = []
    if event.resp_pkts == 0 and event.orig_pkts > 0:
        why.append("No response packets observed")
    if event.dst_port >= 49152:
        why.append("High destination port")
    if event.duration < 0.1:
        why.append("Very short flow duration")
    if event.conn_state in {"s0", "rej"}:
        why.append(f"Connection state: {event.conn_state.upper()}")
    if event.orig_bytes > 1_000_000:
        why.append("Large outbound byte volume")
    return why[:4] or ["Unusual multi-feature pattern relative to fitted baseline"]
