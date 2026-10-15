"""Privately sign independent operator staging attestation with an offline Ed25519 key.

Key generation/distribution and independent operator authorization are external.
Do not invoke this on CI or store private keys in the repository.
"""
from __future__ import annotations

import argparse
import base64
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from networkpulse.deployment_evidence import canonical_json, read_evidence


def sign_attestation(*, attestation_path: Path, private_key_path: Path,
                     signature_path: Path, password: bytes | None = None) -> None:
    """Sign reviewed canonical attestation; refuse insecure private key perms."""
    permission = stat.S_IMODE(private_key_path.stat().st_mode)
    if permission & 0o077:
        raise PermissionError("Operator private key must not be group/world accessible")
    if signature_path.exists():
        raise FileExistsError("Signature already exists; refusing replacement")
    att = read_evidence(attestation_path)
    key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=password)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Staging attestation must use Ed25519 private key")
    digest = base64.b64encode(key.sign(canonical_json(att))) + b"\n"
    signature_path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive file creation: an existing approved detached signature is immutable.
    fd = os.open(signature_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(digest)
            f.flush()
            os.fsync(f.fileno())
        parent_fd = os.open(signature_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except BaseException:
        if signature_path.exists():
            signature_path.unlink()
        raise


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--attestation", type=Path, required=True)
    p.add_argument("--private-key", type=Path, required=True)
    p.add_argument("--signature", type=Path, required=True)
    a = p.parse_args(argv)
    sign_attestation(attestation_path=a.attestation, private_key_path=a.private_key,
                     signature_path=a.signature)
    print("Signed operator attestation; keep private key offline and out of CI")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
