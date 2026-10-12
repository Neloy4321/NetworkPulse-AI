from datetime import datetime

import pytest
from pydantic import ValidationError

from networkpulse.schemas import FlowEvent


def test_idempotency_key_ignore_label_and_json_field_order(samples):
    evt = samples[0]
    again = FlowEvent.model_validate(evt.model_dump(mode="json") | {"label": None})
    assert evt.key() == again.key()


def test_timestamp_must_be_aware(samples):
    evt = samples[0].model_dump()
    evt["timestamp"] = datetime(2026, 1, 1)
    with pytest.raises(ValidationError):
        FlowEvent.model_validate(evt)


def test_bad_ip_and_negative_count_rejected(samples):
    payload = samples[0].model_dump(mode="json")
    payload["src_ip"] = "not-an-ip"
    payload["resp_bytes"] = -1
    with pytest.raises(ValidationError):
        FlowEvent.model_validate(payload)


def test_timezone_normalization(samples):
    evt = samples[0]
    assert evt.timestamp.utcoffset().total_seconds() == 0
