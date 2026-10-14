#!/usr/bin/env python3
"""Offline security-review workstation only: sign an operator-approved payload.

Never run this tool in the NetworkPulse API/worker container. Keep the Ed25519
private key in an offline/HSM-backed security-review process. A signature
authenticates the issuer's approval, NOT the real-world truth of site claims.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from networkpulse.release_approval import canonical_bytes


def main(argv=None):
    p = argparse.ArgumentParser(description="Offline sign a reviewed MLOps release change")
    p.add_argument("--payload", type=Path, required=True)
    p.add_argument("--private-key", type=Path, required=True)
    p.add_argument("--key-id", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError("Signed envelope destination already exists")
    private = load_pem_private_key(args.private_key.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("Release approvals must use Ed25519 private keys")
    payload = json.loads(args.payload.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Approved release payload must be a JSON object")
    document = {
        "schema_version": 1, "key_id": args.key_id,
        "payload": payload,
        "signature": base64.b64encode(private.sign(canonical_bytes(payload))).decode(),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        args.output.unlink(missing_ok=True)
        raise
    print(json.dumps({
        "output": str(args.output), "key_id": args.key_id,
        "signed": True,
        "warning": "Signer approval is not scientific or field-validation proof.",
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
