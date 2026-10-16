"""Missingness-preserving flow representation and fixed feature contract v2.

Version 1 and its deployed IsolationForest remain unchanged. A missing network
counter is represented as None in both training/evaluation and ingestion,
never silently translated to a measured zero. Feature zeros are accompanied
by explicit missing-indicator columns, including for derived ratios.
These features are *not* a quality-qualified or active model.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

V2_FEATURE_CONTRACT = "missingness_aware_flow_v2"
_COUNTERS = ("duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts")
_NULL_TOKENS = frozenset(("-", "", "(empty)", "(unset)"))
Sensor = Literal["zeek", "suricata", "canonical"]


class FlowV2(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timestamp: datetime
    source: Sensor
    uid: str | None = Field(default=None, max_length=160)
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    proto: Literal["tcp", "udp", "icmp", "other"]
    duration: float | None = Field(default=None, ge=0, le=86400)
    orig_bytes: int | None = Field(default=None, ge=0, le=10**13)
    resp_bytes: int | None = Field(default=None, ge=0, le=10**13)
    orig_pkts: int | None = Field(default=None, ge=0, le=10**10)
    resp_pkts: int | None = Field(default=None, ge=0, le=10**10)
    conn_state: str = Field(default="unknown", max_length=24)
    label: Literal["benign", "anomaly"] | None = None

    @field_validator("timestamp")
    @classmethod
    def aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("V2 timestamp must have timezone")
        return value.astimezone(timezone.utc)

    @field_validator("conn_state")
    @classmethod
    def normalize_state(cls, value: str) -> str:
        return value.strip().lower() or "unknown"


def _number(value: Any, *, integer: bool) -> float | int | None:
    if value is None or (isinstance(value, str) and value.strip() in _NULL_TOKENS):
        return None
    if isinstance(value, bool):
        raise ValueError("invalid boolean telemetry measurement")
    if integer:
        # Do not allow 1.5 -> 1 truncation or boolean-as-integer.
        try:
            x = int(value)
        except (ValueError, TypeError, OverflowError) as exc:
            raise ValueError("invalid integer sensor measurement") from exc
        if str(value).strip().lstrip("+") != str(x):
            raise ValueError("fractional or noncanonical integer sensor measurement")
    else:
        try:
            x = float(value)
        except (ValueError, TypeError, OverflowError) as exc:
            raise ValueError("invalid float sensor measurement") from exc
    if not math.isfinite(x) or x < 0:
        raise ValueError("negative, NaN, or infinite sensor measurement")
    return x


def _port(value: Any) -> int:
    result = _number(value, integer=True)
    if result is None:
        raise ValueError("port identity cannot be replaced by a missing value")
    return int(result)


def _proto(value: Any) -> str:
    name = str(value).strip().lower()
    return name if name in ("tcp", "udp", "icmp") else "other"


def from_zeek_v2(row: dict[str, Any]) -> FlowV2:
    """Require network identity; preserve all missing Zeek numeric observations."""
    return FlowV2(
        timestamp=datetime.fromtimestamp(float(row["ts"]), timezone.utc),
        source="zeek", uid=row.get("uid"),
        src_ip=row["id.orig_h"], dst_ip=row["id.resp_h"],
        src_port=_port(row["id.orig_p"]), dst_port=_port(row["id.resp_p"]),
        proto=_proto(row.get("proto", "other")),
        duration=_number(row.get("duration"), integer=False),
        orig_bytes=_number(row.get("orig_bytes"), integer=True),
        resp_bytes=_number(row.get("resp_bytes"), integer=True),
        orig_pkts=_number(row.get("orig_pkts"), integer=True),
        resp_pkts=_number(row.get("resp_pkts"), integer=True),
        conn_state=row.get("conn_state") or "unknown",
    )


def from_suricata_v2(row: dict[str, Any]) -> FlowV2:
    if row.get("event_type") != "flow":
        raise ValueError("only Suricata EVE flow records are accepted")
    flow = row["flow"]
    return FlowV2(
        timestamp=row["timestamp"], source="suricata",
        uid=str(row["flow_id"]) if row.get("flow_id") is not None else None,
        src_ip=row["src_ip"], dst_ip=row["dest_ip"],
        src_port=_port(row["src_port"]), dst_port=_port(row["dest_port"]),
        proto=_proto(row.get("proto", "other")),
        duration=_number(flow.get("age"), integer=False),
        orig_bytes=_number(flow.get("bytes_toserver"), integer=True),
        resp_bytes=_number(flow.get("bytes_toclient"), integer=True),
        orig_pkts=_number(flow.get("pkts_toserver"), integer=True),
        resp_pkts=_number(flow.get("pkts_toclient"), integer=True),
        conn_state=flow.get("state") or "unknown",
    )


def features_v2(flow: FlowV2) -> dict[str, float]:
    """Single fixed vectorization routine used for fit AND scoring.

    A zero placeholder in feature space is only valid together with the
    corresponding explicit missingness flag. Ratios have their own mask.
    No labels, IPs, UID, timestamps, sensor ID or connection-state vocabulary
    are included in any model feature.
    """
    if not isinstance(flow, FlowV2):
        raise TypeError("FlowV2 required: refuse legacy zero-imputed flow")
    numeric = {name: getattr(flow, name) for name in _COUNTERS}
    result: dict[str, float] = {}
    for name, value in numeric.items():
        result["missing_" + name] = float(value is None)
        result["log_" + name] = (
            math.log1p(float(value)) if value is not None else 0.0
        )
    total_bytes = (
        flow.orig_bytes + flow.resp_bytes
        if flow.orig_bytes is not None and flow.resp_bytes is not None else None
    )
    total_pkts = (
        flow.orig_pkts + flow.resp_pkts
        if flow.orig_pkts is not None and flow.resp_pkts is not None else None
    )
    derived = {
        "bytes_per_second": (
            min(1e12, total_bytes / max(.01, flow.duration))
            if total_bytes is not None and flow.duration is not None else None
        ),
        "bytes_per_packet": (
            total_bytes / max(1, total_pkts)
            if total_bytes is not None and total_pkts is not None else None
        ),
        "response_fraction": (
            flow.resp_bytes / max(1, total_bytes)
            if total_bytes is not None else None
        ),
    }
    for name, value in derived.items():
        result["missing_" + name] = float(value is None)
        result[name if name == "response_fraction" else "log_" + name] = (
            (float(value) if name == "response_fraction" else math.log1p(value))
            if value is not None else 0.0
        )
    port_class = (
        "well_known" if flow.dst_port < 1024
        else "registered" if flow.dst_port < 49152
        else "dynamic"
    )
    result["port_class=" + port_class] = 1.0
    result["proto=" + flow.proto] = 1.0
    return result
