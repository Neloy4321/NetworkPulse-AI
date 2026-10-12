"""NetworkPulse CLI: bootstrap, train, ingest local JSONL, replay remotely."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import httpx

from networkpulse.adapters import iter_jsonl
from networkpulse.config import Settings
from networkpulse.detector import Detector, train
from networkpulse.service import ingest
from networkpulse.simulator import sample_flows
from networkpulse.storage import build_sessions


def chunks(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="networkpulse", description="NetworkPulse operations")
    cmd = parser.add_subparsers(dest="command", required=True)

    db = cmd.add_parser("db", help="Manage schema migrations")
    db.add_argument("action", choices=["upgrade", "status", "backup"])
    db.add_argument("--output", type=Path, help="Backup destination (SQLite only)")

    boot = cmd.add_parser("bootstrap", help="Train on a seeded synthetic demo, seed demo events")
    boot.add_argument("--seed", type=int, default=42)
    boot.add_argument("--count", type=int, default=1300)

    generate = cmd.add_parser("generate-demo", help="Write reproducible labeled synthetic flows")
    generate.add_argument("--output", type=Path, default=Path("examples/generated-demo.jsonl"))
    generate.add_argument("--seed", type=int, default=42)
    generate.add_argument("--count", type=int, default=1300)

    fit = cmd.add_parser("train", help="Train on canonical JSONL (chronological split)")
    fit.add_argument("--data", type=Path, required=True)
    fit.add_argument("--model", type=Path, default=None)
    fit.add_argument("--quantile", type=float, default=0.97)
    fit.add_argument("--seed", type=int, default=42)

    local = cmd.add_parser("ingest-file", help="Parse and store local Zeek/Suricata/canonical JSONL")
    local.add_argument("--path", type=Path, required=True)
    local.add_argument("--format", choices=["canonical", "zeek", "suricata"], required=True)

    replay = cmd.add_parser("replay", help="Send an event stream to an API at controlled speed")
    replay.add_argument("--path", type=Path, required=True)
    replay.add_argument("--format", choices=["canonical", "zeek", "suricata"], required=True)
    replay.add_argument("--url", default="http://127.0.0.1:8000")
    replay.add_argument("--batch-size", type=int, default=20)
    replay.add_argument("--delay", type=float, default=0.25, help="seconds between batches")

    args = parser.parse_args(argv)

    if args.command == "generate-demo":
        events = sample_flows(count=args.count, seed=args.seed)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("wt", encoding="utf-8") as stream:
            for event in events:
                stream.write(json.dumps(event.model_dump(mode="json"), separators=(",", ":")) + "\n")
        print(json.dumps({"output": str(args.output), "events": len(events),
                          "note": "Synthetic labels. Not a real network intrusion benchmark."}))
        return 0

    if args.command == "train":
        events = list(iter_jsonl(args.data, "canonical"))
        detector = train(events, quantile=args.quantile, seed=args.seed, source=str(args.data))
        path = args.model or Path(os.getenv("MODEL_PATH", "data/model.joblib"))
        detector.save(path)
        print(json.dumps({"model_path": str(path), **detector.metadata}, indent=2))
        return 0

    if args.command == "replay":
        if args.batch_size < 1 or args.batch_size > 250 or args.delay < 0:
            parser.error("batch-size must be 1..250 and delay must be >=0")
        key = os.getenv("NETWORKPULSE_API_KEY", "")
        if not key:
            parser.error("set NETWORKPULSE_API_KEY for replay")
        records = list(iter_jsonl(args.path, args.format))
        total = {"received": 0, "inserted": 0, "duplicates": 0, "alerts_created": 0}
        with httpx.Client(timeout=20) as client:
            for chunk in chunks(records, args.batch_size):
                response = client.post(
                    args.url.rstrip("/") + "/api/v1/ingest",
                    json={"events": [e.model_dump(mode="json") for e in chunk]},
                    headers={"X-API-Key": key},
                )
                response.raise_for_status()
                for k, v in response.json().items():
                    total[k] += v
                if args.delay:
                    time.sleep(args.delay)
        print(json.dumps(total, indent=2))
        return 0

    if args.command == "db":
        from networkpulse.migrations import backup_sqlite, database_version, upgrade_database
        url = os.getenv("DATABASE_URL", "sqlite:///./data/networkpulse.db")
        if args.action == "upgrade":
            result = upgrade_database(url)
        elif args.action == "backup":
            if args.output is None:
                parser.error("db backup requires --output")
            result = backup_sqlite(url, args.output)
        else:
            result = database_version(url)
        print(json.dumps(result, indent=2))
        return 0

    settings = Settings.from_env()
    sessions = build_sessions(settings.database_url)
    if args.command == "bootstrap":
        flows = sample_flows(count=args.count, seed=args.seed)
        if not settings.model_path.exists():
            detector = train(flows, source="seeded_synthetic_demo", seed=args.seed)
            detector.save(settings.model_path)
        else:
            detector = Detector.load(settings.model_path)
        # Only post-split demo events: evaluation is reported separately from dashboard data.
        with sessions() as session:
            result = ingest(session, detector, flows[int(len(flows) * .75):])
        print(json.dumps({"bootstrap": result, "model": detector.metadata}, indent=2))
        sessions.kw["bind"].dispose()
        return 0
    if args.command == "ingest-file":
        detector = Detector.load(settings.model_path)
        result = {"received": 0, "inserted": 0, "duplicates": 0, "alerts_created": 0}
        batch = []
        with sessions() as session:
            for event in iter_jsonl(args.path, args.format):
                batch.append(event)
                if len(batch) >= settings.max_batch:
                    response = ingest(session, detector, batch)
                    for k, v in response.items():
                        result[k] += v
                    batch = []
            if batch:
                response = ingest(session, detector, batch)
                for k, v in response.items():
                    result[k] += v
        print(json.dumps(result, indent=2))
        sessions.kw["bind"].dispose()
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
