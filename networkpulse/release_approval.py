"""Cryptographically authenticated operator evidence for production model release.

Only an out-of-band provisioned Ed25519 public key in the local trust store
can authorize a production promotion. Trusting the key is an operator task;
signature verification is NOT proof that its factual evaluation claims are true.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_ALLOWED = {"candidate_sha256", "independent_site_verified",
            "live_sensor_contract_verified", "training_test_leakage_audited",
            "approved_by", "evaluation", "issued_at_utc", "expires_at_utc",
            "previous_active", "operation", "change_id"}


def canonical_bytes(payload: dict) -> bytes:
    """Exactly specified canonical bytes; signing code must use this encoding."""
    return json.dumps(payload, sort_keys=True, ensure_ascii=False,
                      allow_nan=False, separators=(",", ":")).encode("utf-8")


def _decode(value: str, size: int) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error, TypeError) as exc:
        raise ValueError("Invalid Ed25519 base64 encoding") from exc
    if len(raw) != size:
        raise ValueError("Invalid Ed25519 key/signature byte count")
    return raw


def _utc_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("Approval timestamps must be strict UTC Z format")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid approval timestamp") from exc
    if dt.tzinfo is None:
        raise ValueError("Approval timestamp lacks timezone")
    return dt.astimezone(timezone.utc)


def verify_signed_approval(
    envelope_path: Path, trust_store_path: Path, *,
    now: datetime | None = None, max_validity_days: int = 7,
) -> dict:
    """Return verified payload and public key identity; no pickle loads.

    Trust files must come from read-only configuration owned by the security
    organization, not from the candidate model, receipt or source repository.
    """
    if not 1 <= max_validity_days <= 30:
        raise ValueError("Invalid validity policy")
    try:
        envelope = json.loads(Path(envelope_path).read_text(encoding="utf-8"))
        trust = json.loads(Path(trust_store_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Signed approval or trust store unavailable/invalid") from exc
    if (not isinstance(envelope, dict) or
            set(envelope) != {"schema_version", "key_id", "payload", "signature"} or
            envelope["schema_version"] != 1):
        raise ValueError("Unsupported signed approval envelope")
    key_id = envelope["key_id"]
    if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
        raise ValueError("Invalid approval signer key ID")
    payload = envelope["payload"]
    if not isinstance(payload, dict) or set(payload) != _ALLOWED:
        raise ValueError("Approval payload is missing or includes unapproved fields")
    if not isinstance(trust, dict) or trust.get("schema_version") != 1:
        raise ValueError("Invalid trusted key registry")
    keys = trust.get("keys")
    if not isinstance(keys, list) or len(keys) > 32:
        raise ValueError("Invalid trusted signer list")
    matches = [key for key in keys if isinstance(key, dict) and key.get("key_id") == key_id]
    if len(matches) != 1 or matches[0].get("enabled") is not True:
        raise ValueError("Signer not uniquely trusted or was revoked")
    key = matches[0]
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            _decode(key["ed25519_public_key_base64"], 32)
        )
        public_key.verify(_decode(envelope["signature"], 64), canonical_bytes(payload))
    except (InvalidSignature, TypeError, KeyError, ValueError) as exc:
        raise ValueError("Production approval signature verification failed") from exc

    if payload["operation"] not in ("promote", "rollback"):
        raise ValueError("Invalid signed model change operation")
    if (not isinstance(payload["change_id"], str)
            or not _KEY_ID.fullmatch(payload["change_id"])):
        raise ValueError("Invalid signed change ID")
    if (payload["previous_active"] is not None and
            (not isinstance(payload["previous_active"], str)
             or not _KEY_ID.fullmatch(payload["previous_active"]))):
        raise ValueError("Invalid signed prior release name")
    issued = _utc_timestamp(payload["issued_at_utc"])
    expires = _utc_timestamp(payload["expires_at_utc"])
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if not issued <= current <= expires or not timedelta(0) < expires - issued <= timedelta(days=max_validity_days):
        raise ValueError("Production approval expired, premature or exceeds time policy")
    return {
        "payload": payload, "signer_key_id": key_id,
        "signature_verified": True,
        "receipt_issued_utc": issued.isoformat(),
        "receipt_expires_utc": expires.isoformat(),
    }
