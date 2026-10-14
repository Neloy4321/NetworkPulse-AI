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
    db.add_argument("action", choices=["upgrade", "status", "check", "backup"])
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

    release = cmd.add_parser(
        "train-release", help="Verify pinned labeled canonical data and stage immutable candidate"
    )
    release.add_argument("--data", type=Path, required=True)
    release.add_argument("--dataset-sha256", required=True,
                         help="Exact SHA-256 computed independently for authorized source")
    release.add_argument("--source-id", required=True,
                         help="Non-sensitive declared provenance identifier")
    release.add_argument("--name", required=True)
    release.add_argument("--root", type=Path, default=Path("data/releases"))
    release.add_argument("--max-events", type=int, default=20000)
    release.add_argument("--min-gap-seconds", type=float, default=0.0)
    release.add_argument("--seed", type=int, default=42)
    release.add_argument("--quantile", type=float, default=.97)
    release.add_argument("--min-f1", type=float, default=0.0)
    release.add_argument("--max-alert-fraction", type=float, default=1.0)
    release.add_argument("--max-fpr-upper-95", type=float, default=None)
    release.add_argument("--registry-root", type=Path,
                         help="Optional local registry for candidate registration (not promotion)")
    verify_release = cmd.add_parser(
        "verify-release", help="Verify candidate bundle SHA without loading joblib"
    )
    verify_release.add_argument("--directory", type=Path, required=True)

    local = cmd.add_parser("ingest-file", help="Parse and store local Zeek/Suricata/canonical JSONL")
    local.add_argument("--path", type=Path, required=True)
    local.add_argument("--format", choices=["canonical", "zeek", "suricata"], required=True)

    replay = cmd.add_parser("replay", help="Send an event stream to an API at controlled speed")
    replay.add_argument("--path", type=Path, required=True)
    replay.add_argument("--format", choices=["canonical", "zeek", "suricata"], required=True)
    replay.add_argument("--url", default="http://127.0.0.1:8000")
    replay.add_argument("--batch-size", type=int, default=20)
    replay.add_argument("--delay", type=float, default=0.25, help="seconds between batches")

    benchmark = cmd.add_parser("benchmark-unsw", help="Offline UNSW-NB15 official train/test comparison")
    benchmark.add_argument("--train", type=Path, required=True)
    benchmark.add_argument("--test", type=Path, required=True)
    benchmark.add_argument("--output", type=Path, default=Path("reports/unsw-benchmark.json"))
    benchmark.add_argument("--max-train", type=int, default=15000)
    benchmark.add_argument("--max-test", type=int, default=12000)
    benchmark.add_argument("--seed", type=int, default=42)

    cic = cmd.add_parser("benchmark-cic", help="Offline CIC-IDS2017 CICFlowMeter CSV comparison")
    cic.add_argument("--train", type=Path, required=True)
    cic.add_argument("--test", type=Path, required=True)
    cic.add_argument("--output", type=Path, default=Path("reports/cic-benchmark.json"))
    cic.add_argument("--max-train", type=int, default=25000)
    cic.add_argument("--max-test", type=int, default=15000)
    cic.add_argument("--seed", type=int, default=42)

    quality = cmd.add_parser("audit-data", help="Audit canonical flow metadata provenance and quality")
    quality.add_argument("--data", type=Path, required=True)
    quality.add_argument("--output", type=Path, default=Path("reports/data-quality.json"))

    enrich = cmd.add_parser("enrich-offline", help="Offline asset and vetted indicator context report")
    enrich.add_argument("--data", type=Path, required=True)
    enrich.add_argument("--format", choices=["canonical", "zeek", "suricata"], required=True)
    enrich.add_argument("--assets", type=Path, required=True)
    enrich.add_argument("--indicators", type=Path, required=True)
    enrich.add_argument("--output", type=Path, default=Path("reports/offline-enrichment.json"))
    enrich.add_argument("--max-events", type=int, default=5000)

    collect = cmd.add_parser("collect", help="Tail a Zeek/Suricata JSONL file to Redis Streams")
    collect.add_argument("--path", type=Path, required=True)
    collect.add_argument("--format", choices=["zeek", "suricata", "canonical"], required=True)
    collect.add_argument("--checkpoint", type=Path, default=Path("data/collector-offset.json"))
    collect.add_argument("--once", action="store_true")

    behavior_worker = cmd.add_parser(
        "behavior-worker", help="Materialize durable cases from finalized ingested UTC windows"
    )
    behavior_worker.add_argument("--once", action="store_true")
    behavior_worker.add_argument("--interval", type=int, default=60)
    behavior_worker.add_argument("--lookback", type=int, default=30)
    behavior_worker.add_argument("--lateness", type=int, default=2)
    behavior_worker.add_argument("--min-ports", type=int, default=12)
    behavior_worker.add_argument("--min-destinations", type=int, default=8)
    behavior_worker.add_argument("--burst-per-minute", type=int, default=120)
    behavior_worker.add_argument("--until", help="Timezone-aware ISO 8601 backfill end")

    monitor = cmd.add_parser(
        "mlops-monitor", help="Persist drift/lineage evidence on the deployed pinned model"
    )
    monitor.add_argument("--once", action="store_true")
    monitor.add_argument("--interval", type=int, default=300)
    monitor.add_argument("--delay-minutes", type=int, default=10)
    monitor.add_argument("--lookback-hours", type=int, default=3)
    monitor.add_argument("--max-rows", type=int, default=5000)
    monitor.add_argument("--expected-sha256", help="Trusted deployed model SHA-256")
    monitor.add_argument("--start", help="ISO 8601 UTC start for operator-controlled backfill")
    monitor.add_argument("--end", help="ISO 8601 UTC end for operator-controlled backfill")

    worker = cmd.add_parser("worker", help="Consume Redis Streams and commit scored flows")
    worker.add_argument("--consumer", default="networkpulse-worker-1")
    worker.add_argument("--once", action="store_true")

    explain_cmd = cmd.add_parser("explain-model", help="Bounded model-score sensitivity audit")
    explain_cmd.add_argument("--data", type=Path, required=True)
    explain_cmd.add_argument("--model", type=Path, default=Path("data/model.joblib"))
    explain_cmd.add_argument("--output", type=Path, default=Path("reports/score-sensitivity.json"))
    explain_cmd.add_argument("--top-k", type=int, default=3)
    explain_cmd.add_argument("--max-events", type=int, default=20)

    drift = cmd.add_parser("drift-report", help="Audit drift against a trusted model baseline")
    drift.add_argument("--data", type=Path, required=True)
    drift.add_argument("--model", type=Path, default=Path("data/model.joblib"))
    drift.add_argument("--output", type=Path, default=Path("reports/drift.json"))

    registry = cmd.add_parser("model-registry", help="Register, gate, promote, shadow and roll back trusted models")
    registry.add_argument("action", choices=["register", "status", "promote", "rollback", "shadow"])
    registry.add_argument("--name", help="Immutable candidate name")
    registry.add_argument("--file", type=Path, help="Locally trained, trusted model artifact")
    registry.add_argument("--root", type=Path, default=Path("data/registry"))
    registry.add_argument("--active", type=Path, default=Path("data/model.joblib"))
    registry.add_argument("--min-f1", type=float, default=0.0)
    registry.add_argument("--max-alert-fraction", type=float, default=1.0)
    registry.add_argument("--max-fpr-upper-95", type=float, default=None,
                          help="Opt-in registration FPR 95% Wilson upper bound gate")
    registry.add_argument("--production", action="store_true",
                          help="Require independent-site, live-sensor and human evidence")
    registry.add_argument("--evidence", type=Path,
                          help="Operator-audited production validation receipt JSON")
    registry.add_argument("--seed", type=int, default=42)

    archive = cmd.add_parser("archive", help="Archive old unalerted flows; dry-run unless --commit")
    archive.add_argument("--before-days", type=int, default=30)
    archive.add_argument("--output", type=Path, required=True)
    archive.add_argument("--max-rows", type=int, default=5000)
    archive.add_argument("--commit", action="store_true")

    args = parser.parse_args(argv)

    if args.command == "verify-release":
        from networkpulse.training_release import verify_candidate
        print(json.dumps(verify_candidate(args.directory), indent=2))
        return 0

    if args.command == "train-release":
        from networkpulse.data_quality import fingerprint
        from networkpulse.training_release import build_candidate
        if not args.data.is_file() or args.data.stat().st_size > 250_000_000:
            parser.error("training data must be an existing file no larger than 250 MB")
        if fingerprint(args.data) != args.dataset_sha256:
            parser.error("training data SHA-256 differs from pinned source checksum")
        if not 100 <= args.max_events <= 100000:
            parser.error("max-events must be 100..100000")
        loaded = []
        for event in iter_jsonl(args.data, "canonical"):
            loaded.append(event)
            if len(loaded) > args.max_events:
                parser.error("training dataset exceeds row cap; no silent truncation")
        result = build_candidate(
            loaded, name=args.name, root=args.root,
            dataset_sha256=args.dataset_sha256, source_id=args.source_id,
            seed=args.seed, quantile=args.quantile, max_events=args.max_events,
            min_boundary_gap_seconds=args.min_gap_seconds,
            min_f1=args.min_f1, max_alert_fraction=args.max_alert_fraction,
            max_fpr_upper_95=args.max_fpr_upper_95,
            dataset_selection="complete_canonical_file",
        )
        if args.registry_root:
            from networkpulse.model_registry import ModelRegistry
            registered = ModelRegistry(args.registry_root).register(
                args.name, Path(result["model_path"]), min_f1=args.min_f1,
                max_alert_fraction=args.max_alert_fraction,
                max_fpr_upper_95=args.max_fpr_upper_95,
                release_directory=Path(result["directory"]),
            )
            result["registry"] = {
                "root": str(args.registry_root), "sha256": registered["sha256"],
                "state": "registered_candidate_not_promoted",
            }
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "model-registry":
        from networkpulse.model_registry import ModelRegistry
        managed = ModelRegistry(args.root)
        if args.action in {"register", "promote", "shadow"} and not args.name:
            parser.error("model-registry action requires --name")
        if args.action == "register":
            if not args.file:
                parser.error("model-registry register requires --file")
            result = managed.register(args.name, args.file, min_f1=args.min_f1,
                                      max_alert_fraction=args.max_alert_fraction,
                                      max_fpr_upper_95=args.max_fpr_upper_95)
        elif args.action == "status":
            result = managed.status()
        elif args.action == "promote":
            result = managed.promote(args.name, args.active,
                                     production=args.production,
                                     evidence_path=args.evidence,
                                     max_fpr_upper_95=args.max_fpr_upper_95 or .05)
        elif args.action == "rollback":
            result = managed.rollback(args.active, production=args.production,
                                      evidence_path=args.evidence)
        else:
            result = managed.shadow(args.name, args.active,
                                    sample_flows(count=300, seed=args.seed)[-75:])
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "archive":
        from networkpulse.retention import archive_unalerted, cutoff_days
        settings = Settings.from_env()
        maker = build_sessions(settings.database_url)
        try:
            with maker() as session:
                result = archive_unalerted(session, before=cutoff_days(args.before_days),
                                           destination=args.output, commit=args.commit,
                                           max_rows=args.max_rows)
        finally:
            maker.kw["bind"].dispose()
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "mlops-monitor":
        from datetime import datetime, timedelta
        from networkpulse.ops_health import mark_success
        from networkpulse.mlops_monitor import completed_hour, run_monitor
        settings = Settings.from_env()
        expected = args.expected_sha256 or settings.model_sha256
        if not expected or len(expected) != 64:
            parser.error("mlops-monitor requires trusted MODEL_SHA256 / --expected-sha256")
        if not 60 <= args.interval <= 3600 or not 1 <= args.lookback_hours <= 24:
            parser.error("invalid monitoring cadence/lookback")
        if bool(args.start) != bool(args.end):
            parser.error("--start and --end must be supplied together")
        if args.start and not args.once:
            parser.error("manual backfill --start/--end requires --once")
        maker = build_sessions(settings.database_url)
        try:
            while True:
                if args.start:
                    windows = [(datetime.fromisoformat(args.start.replace("Z", "+00:00")),
                                datetime.fromisoformat(args.end.replace("Z", "+00:00")))]
                else:
                    low, finish = completed_hour(delay_minutes=args.delay_minutes)
                    windows = [
                        (low - timedelta(hours=index), finish - timedelta(hours=index))
                        for index in reversed(range(args.lookback_hours))
                    ]
                for start, end in windows:
                    with maker() as session:
                        result = run_monitor(
                            session, model_path=settings.model_path,
                            expected_sha256=expected, start=start, end=end,
                            max_rows=args.max_rows,
                        )
                    print(json.dumps(result), flush=True)
                # A completed full monitoring cycle is required before
                # advertising health; a failed window never updates it.
                mark_success(Path("/tmp/networkpulse-mlops-heartbeat.json"), "mlops")
                if args.once:
                    break
                time.sleep(args.interval)
        finally:
            maker.kw["bind"].dispose()
        return 0

    if args.command == "behavior-worker":
        from datetime import datetime
        from networkpulse.ops_health import mark_success
        from networkpulse.behavior_cases import materialize_findings
        if not 5 <= args.interval <= 3600:
            parser.error("behavior-worker interval must be 5..3600 seconds")
        settings = Settings.from_env()
        maker = build_sessions(settings.database_url)
        try:
            until = datetime.fromisoformat(args.until.replace("Z", "+00:00")) if args.until else None
            if until and not args.once:
                parser.error("--until requires --once (backfill cannot run as a daemon)")
            while True:
                with maker() as session:
                    outcome = materialize_findings(
                        session, until=until, lookback_minutes=args.lookback,
                        lateness_minutes=args.lateness, min_ports=args.min_ports,
                        min_destinations=args.min_destinations,
                        burst_per_minute=args.burst_per_minute,
                    )
                print(json.dumps(outcome), flush=True)
                mark_success(Path("/tmp/networkpulse-behavior-heartbeat.json"), "behavior")
                if args.once:
                    break
                time.sleep(args.interval)
        finally:
            maker.kw["bind"].dispose()
        return 0

    if args.command in {"collect", "worker"}:
        from networkpulse.streaming.redis_streams import FlowStream, connect, process_events
        from networkpulse.streaming.collector import LogCollector
        queue = FlowStream(connect(os.getenv("REDIS_URL", "redis://localhost:6379/0")))
        queue.initialize()
        if args.command == "worker":
            result = process_events(queue, args.consumer, settings=Settings.from_env(), once=args.once)
        else:
            collector = LogCollector(args.path, args.format, args.checkpoint, queue.enqueue)
            result = collector.poll_once() if args.once else collector.follow()
        if result is not None:
            print(json.dumps(result, indent=2))
        return 0

    if args.command == "enrich-offline":
        from itertools import islice
        from networkpulse.intel_enrichment import enrich_flow, load_assets, load_indicators
        from networkpulse.data_quality import fingerprint
        if not 1 <= args.max_events <= 100000:
            parser.error("max-events must be 1..100000")
        assets, indicators = load_assets(args.assets), load_indicators(args.indicators)
        entries = [enrich_flow(e, assets, indicators)
                   for e in islice(iter_jsonl(args.data, args.format), args.max_events)]
        report = {"source": str(args.data), "source_sha256": fingerprint(args.data),
                  "events_evaluated": len(entries), "indicator_count": len(indicators),
                  "assets_count": len(assets), "items": entries,
                  "warning": "No feed is independently validated and no matches prove an attack."}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"report": str(args.output),
                          "events_evaluated": len(entries)}, indent=2))
        return 0

    if args.command == "audit-data":
        from networkpulse.data_quality import write_quality_report
        flows = list(iter_jsonl(args.data, 'canonical'))
        report = write_quality_report(flows, args.data, args.output)
        print(json.dumps({'report': str(args.output), 'records': report['record_count'],
                          'duplicates': report['duplicate_count']}, indent=2))
        return 0

    if args.command == "benchmark-cic":
        from networkpulse.evaluation.cic import evaluate_cic
        report = evaluate_cic(args.train, args.test, seed=args.seed,
                              max_train=args.max_train, max_test=args.max_test)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n",
                               encoding="utf-8")
        print(json.dumps({"report": str(args.output), "test_rows": report["sample_counts"]["test"],
                          "true_chronological_validation_verified": False}, indent=2))
        return 0

    if args.command == "benchmark-unsw":
        from networkpulse.evaluation.unsw import evaluate_unsw, write_report
        output = evaluate_unsw(args.train, args.test, max_train=args.max_train,
                               max_test=args.max_test, seed=args.seed)
        write_report(output, args.output)
        print(json.dumps({"report": str(args.output), "results": output["evaluation"],
                          "temporal_split_verified": False}, indent=2))
        return 0

    if args.command == "explain-model":
        from itertools import islice
        if not 1 <= args.max_events <= 25 or not 1 <= args.top_k <= 8:
            parser.error("--max-events must be 1..25 and --top-k must be 1..8")
        events = list(islice(iter_jsonl(args.data, "canonical"), args.max_events))
        explanations = Detector.load(args.model).sensitivity_explanations(
            events, top_k=args.top_k
        )
        report = {
            "input_events": len(events), "feature_score_sensitivities": explanations,
            "no_original_event_payloads_exported": True,
            "method_warning": (
                "One numeric feature is independently replaced with its median "
                "benign training value. NOT SHAP, causal impact or proof of maliciousness."
            ),
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"report": str(args.output), "events": len(events)}, indent=2))
        return 0

    if args.command == "drift-report":
        from networkpulse.drift import drift_report
        events = list(iter_jsonl(args.data, "canonical"))
        report = drift_report(Detector.load(args.model), events)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"report": str(args.output), "events": len(events),
                          "worst_psi": report["worst_psi"]}, indent=2))
        return 0

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
        if args.action == "check" and not result.get("ready", False):
            return 1  # Deployment must fail closed on a pending schema migration.
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
