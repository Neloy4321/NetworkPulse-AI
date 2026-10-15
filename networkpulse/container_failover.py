"""Actual, controlled PostgreSQL/Redis SIGKILL and same-node restart drill.

Only newly created, owned, loopback-only disposable Docker containers may be
stopped. This test is not multi-node HA or a real-site RPO/RTO certification.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select, create_engine

from networkpulse.migrations import upgrade_database
from networkpulse.schemas import FlowEvent
from networkpulse.service import ingest
from networkpulse.simulator import sample_flows
from networkpulse.staging_load import percentile, write_report
from networkpulse.storage import NetworkEvent, build_sessions
from networkpulse.streaming.redis_streams import FlowStream

CONSENT = "I_ACCEPT_EPHEMERAL_CONTAINERS"
LABEL_OWNER = "networkpulse.isolated_failover_drill"
LABEL_RUN = "networkpulse.failover_run_id"
DATABASE = "networkpulse_drill_ci"


def require_disposable_local_docker(confirmed: bool) -> None:
    if not confirmed or os.getenv("NETWORKPULSE_ALLOW_ISOLATED_DOCKER_DRILL") != CONSENT:
        raise ValueError("Explicit disposable Docker lab consent is required")
    if os.getenv("DOCKER_HOST") or os.getenv("DOCKER_CONTEXT"):
        raise ValueError("Remote/overridden Docker daemon is not permitted")
    try:
        mode = os.stat("/var/run/docker.sock").st_mode
    except OSError as exc:
        raise ValueError("Local Docker socket is required") from exc
    if not stat.S_ISSOCK(mode):
        raise ValueError("Docker endpoint must be a local Unix socket")
    result = subprocess.run(
        ["docker", "context", "show"], capture_output=True,
        text=True, timeout=10, check=True,
    )
    if result.stdout.strip() != "default":
        raise ValueError("A non-default Docker context is prohibited")


def _docker(*args: str, timeout: float = 40) -> str:
    """Never echo Docker arguments or stderr that may contain a credential."""
    try:
        p = subprocess.run(
            ["docker", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Local ephemeral Docker command unavailable") from exc
    if p.returncode:
        raise RuntimeError("Local disposable Docker operation failed")
    return p.stdout.strip()


@dataclass(frozen=True)
class OwnedContainer:
    container_id: str
    name: str
    run_id: str
    image: str


def verified_owned(container: OwnedContainer) -> None:
    """Check identity before any destructive stop/start/removal."""
    obj = json.loads(_docker("inspect", container.container_id))[0]
    labels = obj["Config"]["Labels"] or {}
    if (obj["Id"] != container.container_id
            or obj["Name"] != "/" + container.name
            or labels.get(LABEL_OWNER) != "true"
            or labels.get(LABEL_RUN) != container.run_id
            or obj["Config"]["Image"] != container.image):
        raise ValueError("Docker ownership labels/name/image mismatch; refusing mutation")


def _published_loopback_port(container: OwnedContainer, service_port: int) -> int:
    verified_owned(container)
    ports = _docker("port", container.container_id, f"{service_port}/tcp")
    for line in ports.splitlines():
        if line.startswith("127.0.0.1:"):
            port = int(line.rsplit(":", 1)[1])
            if 1024 <= port <= 65535:
                return port
    raise RuntimeError("Expected local-only ephemeral Docker port not found")


def _wait_ready(check, *, phase: str, timeout_seconds: float = 45) -> float:
    started = time.monotonic()
    while time.monotonic() - started < timeout_seconds:
        try:
            if check():
                return round(time.monotonic() - started, 3)
        except Exception:
            pass
        time.sleep(.2)
    raise TimeoutError("Disposable service failed to return to readiness: " + phase)


class DisposableLab:
    """No caller-provided container names/IDs or existing service endpoints."""

    def __init__(self, run_id: str):
        self.run_id = run_id
        self.owned: list[OwnedContainer] = []

    def create(self, *, service: str, image: str, port: int,
               extra_args: list[str], command: list[str]) -> tuple[OwnedContainer, int]:
        if service not in {"postgres", "redis"}:
            raise ValueError("Unsupported disposable service")
        if image not in {"postgres:16-alpine", "redis:7-alpine"}:
            raise ValueError("Unapproved lab image")
        name = f"networkpulse-failover-{self.run_id}-{service}"
        output = _docker(
            "run", "-d", "--name", name,
            "--label", f"{LABEL_OWNER}=true",
            "--label", f"{LABEL_RUN}={self.run_id}",
            "-p", f"127.0.0.1::{port}",
            *extra_args, image, *command, timeout=75,
        )
        if len(output) != 64 or any(c not in "0123456789abcdef" for c in output):
            raise RuntimeError("Docker did not return an expected container ID")
        owned = OwnedContainer(output, name, self.run_id, image)
        self.owned.append(owned)
        return owned, _published_loopback_port(owned, port)

    def kill(self, container: OwnedContainer) -> None:
        verified_owned(container)
        _docker("kill", "--signal=KILL", container.container_id)

    def restart(self, container: OwnedContainer) -> None:
        verified_owned(container)
        _docker("start", container.container_id)

    def cleanup(self) -> None:
        for item in reversed(self.owned):
            verified_owned(item)
            _docker("rm", "--force", item.container_id)


def _database_ids(maker, keys: set[str]) -> set[str]:
    with maker() as session:
        return set(session.scalars(
            select(NetworkEvent.id).where(NetworkEvent.id.in_(sorted(keys)))
        ).all())


def execute_isolated_restart_drill(lab: DisposableLab) -> dict:
    """Actual service interruption, pending recovery and SQL ID reconciliation."""
    import redis
    from networkpulse.detector import train

    password = secrets.token_urlsafe(24)
    pg, pg_port = lab.create(
        service="postgres", image="postgres:16-alpine", port=5432,
        extra_args=[
            "-e", f"POSTGRES_PASSWORD={password}",
            "-e", "POSTGRES_USER=networkpulse_drill",
            "-e", f"POSTGRES_DB={DATABASE}",
        ], command=[],
    )
    rd, rd_port = lab.create(
        service="redis", image="redis:7-alpine", port=6379,
        extra_args=[], command=[
            "redis-server", "--appendonly", "yes", "--appendfsync", "always",
            "--save", "", "--maxmemory-policy", "noeviction",
        ],
    )
    db_url = (
        f"postgresql+psycopg://networkpulse_drill:{password}"
        f"@127.0.0.1:{pg_port}/{DATABASE}"
    )
    client = redis.Redis.from_url(
        f"redis://127.0.0.1:{rd_port}/1", decode_responses=True,
        socket_connect_timeout=1, socket_timeout=2, retry_on_timeout=False,
    )
    maker = None
    engine = create_engine(db_url, pool_pre_ping=True, connect_args={"connect_timeout": 2})
    try:
        def sql_ready():
            with engine.connect():
                return True
        _wait_ready(sql_ready, phase="postgres_initial")
        _wait_ready(client.ping, phase="redis_initial")
        upgrade_database(db_url)
        maker = build_sessions(db_url)
        model = train(sample_flows(320, seed=7711), seed=7711)
        events = sample_flows(220, seed=7712)[:120]
        keys = {event.key() for event in events}
        if len(keys) != len(events) or _database_ids(maker, keys):
            raise RuntimeError("Input IDs were duplicated or already present")
        stream = f"networkpulse:ci:ephemeral-failover:{lab.run_id}"
        queue = FlowStream(client, stream=stream, group="ci", max_backlog=200)
        queue.initialize()
        acked = 0
        queue_seconds: list[float] = []
        started = time.monotonic()

        def commit(batch):
            with maker() as session:
                ingest(session, model, batch)

        def observed_ack(ids):
            nonlocal acked
            seconds, micros = client.time()
            now_ms = seconds * 1000 + micros // 1000
            queue_seconds.extend([
                max(0., (now_ms - int(value.split("-", 1)[0])) / 1000)
                for value in ids
            ])
            acked += len(ids)

        def drain(consumer: str, target: int):
            attempts = 0
            while acked < target and attempts < 30:
                attempts += 1
                receipt = queue.consume_batch_once(
                    consumer, commit, FlowEvent.model_validate,
                    recover=True, recover_idle_ms=0, block_ms=30,
                    on_committed=observed_ack,
                )
                if receipt["retried"] or receipt["dead_lettered"]:
                    raise RuntimeError("Recovery left uncommitted or invalid deliveries")
            if acked != target:
                raise RuntimeError("Stream failed to drain all acknowledged flows")

        for event in events[:60]:
            queue.enqueue(event.model_dump(mode="json"))
        first = queue.consume_batch_once(
            "initial", commit, FlowEvent.model_validate,
            recover=False, block_ms=30, on_committed=observed_ack,
        )
        if first["processed"] != 25 or acked != 25:
            raise RuntimeError("Initial PostgreSQL transaction/ACK failed")
        lab.kill(pg)
        engine.dispose()
        db_failure = queue.consume_batch_once(
            "postgres-down", commit, FlowEvent.model_validate,
            recover=False, block_ms=30,
        )
        if (db_failure["retried"] != 25 or client.xlen(stream) != 35
                or client.xpending(stream, queue.group)["pending"] != 25):
            raise RuntimeError("Real PostgreSQL outage failed to retain pending flows")
        pg_restart_start = time.monotonic()
        lab.restart(pg)
        pg_ready_seconds = _wait_ready(sql_ready, phase="postgres_after_sigkill")
        pg_restart_total = round(time.monotonic() - pg_restart_start, 3)
        maker.kw["bind"].dispose()
        drain("after-postgres-restart", 60)
        known = {event.key() for event in events[:60]}
        if _database_ids(maker, known) != known:
            raise RuntimeError("PostgreSQL WAL recovery lost committed rows")

        for event in events[60:]:
            queue.enqueue(event.model_dump(mode="json"))
        claimed = queue._messages("redis-pending-before-kill", block_ms=30, count=20)
        if len(claimed) != 20 or client.xpending(stream, queue.group)["pending"] != 20:
            raise RuntimeError("Cannot establish real Redis pending state")
        saved_stream_depth = client.xlen(stream)
        lab.kill(rd)
        try:
            client.ping()
        except redis.exceptions.RedisError:
            pass
        else:
            raise RuntimeError("Redis was reachable after forced SIGKILL")
        redis_restart_start = time.monotonic()
        lab.restart(rd)
        redis_ready_seconds = _wait_ready(client.ping, phase="redis_after_sigkill")
        redis_restart_total = round(time.monotonic() - redis_restart_start, 3)
        if (client.xlen(stream) != saved_stream_depth
                or client.xpending(stream, queue.group)["pending"] != 20):
            raise RuntimeError("Redis AOF restart lost pending stream state")
        drain("after-redis-restart", len(events))
        if (client.xlen(stream) or client.xpending(stream, queue.group)["pending"]
                or client.xlen(queue.dead_letter)):
            raise RuntimeError("Pending/stream/DLQ not empty after recovery")
        stored = _database_ids(maker, keys)
        if stored != keys or acked != len(events) or len(queue_seconds) != len(events):
            raise RuntimeError("Committed and acknowledged flow IDs failed reconciliation")
        return {
            "schema_version": 1, "status": "passed",
            "scope": "isolated_ephemeral_single_node_sigkill_restart_not_ha_failover",
            "run_id": lab.run_id,
            "postgres": {
                "fault": "real_sigkill_same_container_restart",
                "readiness_seconds": pg_ready_seconds,
                "restart_to_ready_seconds": pg_restart_total,
                "unacknowledged_at_outage": db_failure["retried"],
            },
            "redis": {
                "fault": "real_sigkill_aof_same_container_restart",
                "appendfsync": "always",
                "readiness_seconds": redis_ready_seconds,
                "restart_to_ready_seconds": redis_restart_total,
                "pending_before_and_after": len(claimed),
            },
            "reconciliation": {
                "unique_published": len(events), "acknowledged_deliveries": acked,
                "postgres_unique_persisted": len(stored), "missing_event_ids": 0,
                "stream_remaining": 0, "pending_remaining": 0,
                "dead_letter_remaining": 0,
            },
            "queue_to_ack_seconds": {
                "p50": percentile(queue_seconds, .5),
                "p95": percentile(queue_seconds, .95),
                "p99": percentile(queue_seconds, .99),
            },
            "observed_elapsed_seconds": round(time.monotonic() - started, 3),
            "limitations": [
                "Synthetic CI corpus; no field detection performance evidence",
                "Single-node crash and restart, not multi-node failover or HA",
                "Disposable Redis uses appendfsync always; not site durability policy",
                "Zero missing records for this run, not certified production RPO/RTO",
            ],
        }
    finally:
        if maker is not None:
            maker.kw["bind"].dispose()
        engine.dispose()
        client.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-disposable-lab", action="store_true")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    require_disposable_local_docker(args.confirm_disposable_lab)
    if args.report.exists():
        raise ValueError("Evidence already exists; never overwrite a previous drill")
    run_id = uuid.uuid4().hex
    lab = DisposableLab(run_id)
    try:
        result = execute_isolated_restart_drill(lab)
    except Exception as exc:
        result = {
            "schema_version": 1, "run_id": run_id, "status": "failed",
            "scope": "isolated_ephemeral_single_node_sigkill_restart_not_ha_failover",
            "failure_class": type(exc).__name__,
            "safe_failure": str(exc) if type(exc) in (RuntimeError, TimeoutError, ValueError)
            and str(exc).startswith((
                "Initial ", "Real PostgreSQL ", "Cannot establish ",
                "Redis ", "Stream ", "Committed ", "Pending/stream/",
                "Input IDs ", "Recovery ", "Local disposable ",
                "Disposable service ",
            )) else "See private runner operational logs",
        }
    try:
        lab.cleanup()
    except Exception:
        result["status"] = "failed"
        result["cleanup_status"] = "failed_manual_operator_review_required"
    else:
        result["cleanup_status"] = "verified_owned_containers_removed"
    write_report(args.report, result)
    print(json.dumps({"status": result["status"],
                      "safe_failure": result.get("safe_failure"),
                      "cleanup_status": result["cleanup_status"]}), flush=True)
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
