"""Validated canonical flow contract shared by adapters, storage and scoring."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

Protocol = Literal["tcp", "udp", "icmp", "other"]


class FlowEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    source: Literal["zeek", "suricata", "canonical", "simulator"]
    uid: str | None = Field(default=None, max_length=160)
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    proto: Protocol
    duration: float = Field(ge=0, le=86400)
    orig_bytes: int = Field(ge=0, le=10**13)
    resp_bytes: int = Field(ge=0, le=10**13)
    orig_pkts: int = Field(ge=0, le=10**10)
    resp_pkts: int = Field(ge=0, le=10**10)
    conn_state: str = Field(default="unknown", max_length=24)
    label: Literal["benign", "anomaly"] | None = None

    @field_validator("timestamp")
    @classmethod
    def timestamp_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("conn_state")
    @classmethod
    def state_normalized(cls, value: str) -> str:
        return value.strip().lower() or "unknown"

    def key(self) -> str:
        """Stable idempotency key independent of JSON property order or local time zone."""
        payload = self.model_dump(mode="json", exclude={"label"})
        payload["timestamp"] = self.timestamp.isoformat()
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()[:32]


class FlowBatch(BaseModel):
    events: list[FlowEvent] = Field(min_length=1, max_length=250)


class AlertPatch(BaseModel):
    status: Literal["open", "investigating", "resolved", "false_positive"]
    note: str = Field(min_length=3, max_length=1500)


class ModelMetadata(BaseModel):
    schema_version: int
    trained_at: datetime
    source: str
    calibration_quantile: float
    threshold: float
    feature_count: int
    training_rows: int
    calibration_rows: int
    evaluation_rows: int
    metrics: dict[str, float | int | None]
