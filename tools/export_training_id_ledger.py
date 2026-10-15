"""Export verified canonical IDs for EXACT training corpus; no payload export.

This ledger is a mechanical leakage check, not proof of capture independence.
If original training data cannot be reproduced, do not claim external-domain
independence on the basis of an invented ledger or an approximate data subset.
"""
from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

from networkpulse.generalization_evidence import (
    digest_file, valid_sha, normalized_flow_fingerprint,
)


def export_training_ledger(source: Path, expected_sha256: str, output: Path,
                           *, max_rows: int = 500_000, reader=None) -> dict:
    if not valid_sha(expected_sha256) or digest_file(source) != expected_sha256:
        raise ValueError("Original training source SHA256 mismatch")
    if output.exists():
        raise FileExistsError("Training ID ledger already exists")
    if not (100 <= max_rows <= 500_000):
        raise ValueError("Training ledger row cap must be 100..500000")
    if reader is None:
        from networkpulse.adapters import iter_jsonl
        reader = iter_jsonl
    keys = set()
    records = []
    for evt in reader(source, "canonical"):
        key = evt.key()
        if key in keys:
            raise ValueError("Duplicate canonical training event key")
        if len(keys) >= max_rows:
            raise ValueError("Training source exceeds bounded row limit")
        keys.add(key)
        records.append((key, normalized_flow_fingerprint(evt)))
    if not keys or digest_file(source) != expected_sha256:
        raise ValueError("Training corpus is empty or modified during indexing")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, pending = tempfile.mkstemp(prefix=".training-ids-", dir=output.parent)
    try:
        with os.fdopen(descriptor, "wt", encoding="utf-8") as f:
            os.fchmod(f.fileno(), 0o600)
            for key, fingerprint in sorted(records):
                f.write(key + "\t" + fingerprint + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.link(pending, output)
        parent_fd = os.open(output.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if os.path.exists(pending):
            os.unlink(pending)
    return {"training_events": len(keys), "source_sha256": expected_sha256,
            "ledger_sha256": digest_file(output), "contains_flow_payloads": False}


def main(argv: list[str] | None = None) -> int:
    import json
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--original-training-corpus", type=Path, required=True)
    p.add_argument("--source-sha256", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--max-rows", type=int, default=500_000)
    a = p.parse_args(argv)
    report = export_training_ledger(
        a.original_training_corpus, a.source_sha256, a.output,
        max_rows=a.max_rows,
    )
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
