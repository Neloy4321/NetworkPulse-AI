"""Reconstruct restricted training overlap ledger from exact pinned source bytes.

Do not publish the output TSV; hashed network metadata may be reidentifiable.
This does NOT serialize models or depend on source labels from external targets.
"""
from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path

from networkpulse.evaluation.frozen_rf_research import (
    fixed_protocol, private_ledger_bytes, write_private_training_ledger,
)
from networkpulse.evaluation.live_unsw import read_reservoir
from networkpulse.evaluation.source_only_feature_audit import SOURCE_EXPECTED_BYTES
from networkpulse.evaluation.source_only_loco import MEMBERS, MEMBER_SEEDS, SAMPLE_PER_MEMBER
from networkpulse.evaluation.unsw_to_toniot import UNSW_SHA, digest, unique


def rebuild(source_zip: Path, manifest_path: Path, output: Path) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (manifest.get("status") != "source_only_supervised_research_bundle_frozen"
            or manifest.get("production_approved") is not False
            or manifest.get("protocol") != fixed_protocol()
            or manifest.get("source_zip_sha256") != UNSW_SHA):
        raise ValueError("trusted frozen research source manifest mismatch")
    if source_zip.stat().st_size != SOURCE_EXPECTED_BYTES or digest(source_zip) != UNSW_SHA:
        raise ValueError("restricted raw training source SHA/size mismatch")
    flows = []
    with zipfile.ZipFile(source_zip) as archive:
        for member, seed in zip(MEMBERS, MEMBER_SEEDS):
            rows, info = read_reservoir(archive, member, SAMPLE_PER_MEMBER, seed)
            if len(rows) != SAMPLE_PER_MEMBER or info["source_file"] != member:
                raise ValueError("source member incomplete")
            flows.extend(rows)
    if digest(source_zip) != UNSW_SHA:
        raise ValueError("restricted raw source changed while restoring ledger")
    selected, excluded = unique(flows)
    if (len(selected) != manifest.get("training_unique")
            or excluded != manifest.get("duplicates_excluded")):
        raise ValueError("source sample identity counts changed")
    material = private_ledger_bytes(selected)
    from hashlib import sha256
    sha = sha256(material).hexdigest()
    if sha != manifest.get("training_ledger_sha256"):
        raise ValueError("regenerated source training ledger checksum differs")
    if output.exists():
        raise ValueError("refusing to replace existing private training ledger")
    written = write_private_training_ledger(output, material)
    if written != sha:
        output.unlink(missing_ok=True)
        raise ValueError("private ledger mutated during reconstruction")
    return {
        "status": "private_original_training_ledger_rebuilt",
        "ledger_sha256": written, "original_training_rows": len(selected),
        "raw_identifiers_published": False, "production_approved": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unsw-zip", type=Path, required=True)
    parser.add_argument("--frozen-manifest", type=Path, required=True)
    parser.add_argument("--private-output", type=Path, required=True)
    args = parser.parse_args()
    result = rebuild(args.unsw_zip, args.frozen_manifest, args.private_output)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
