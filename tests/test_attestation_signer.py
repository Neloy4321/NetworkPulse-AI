"""Operator detached-signature tests (ephemeral fixture keys only)."""
import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from networkpulse.deployment_evidence import canonical_json
from tools.sign_staging_attestation import sign_attestation


def test_signer_writes_owner_only_verified_detached_signature(tmp_path):
    priv = Ed25519PrivateKey.generate()
    keyfile = tmp_path / "operator.pem"
    keyfile.write_bytes(priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    keyfile.chmod(0o600)
    info = {"scope": "independent_staging", "approved": True}
    attfile = tmp_path / "attestation.json"
    attfile.write_text(json.dumps(info))
    out = tmp_path / "signed" / "attestation.sig"
    sign_attestation(attestation_path=attfile, private_key_path=keyfile,
                     signature_path=out)
    assert out.stat().st_mode & 0o777 == 0o600
    priv.public_key().verify(base64.b64decode(out.read_text().strip()),
                             canonical_json(info))
    with pytest.raises(FileExistsError):
        sign_attestation(attestation_path=attfile, private_key_path=keyfile,
                         signature_path=out)


def test_reject_private_operator_key_world_permissions(tmp_path):
    priv = Ed25519PrivateKey.generate()
    keyfile = tmp_path / "insecure.pem"
    keyfile.write_bytes(priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    keyfile.chmod(0o644)
    attfile = tmp_path / "att.json"
    attfile.write_text('{"reviewed":true}')
    with pytest.raises(PermissionError):
        sign_attestation(attestation_path=attfile, private_key_path=keyfile,
                         signature_path=tmp_path / "out.sig")
