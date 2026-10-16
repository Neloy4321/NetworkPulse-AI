"""Real process-kill/restart of owned, disposable Stage B PostgreSQL/Redis services.

CI-only: no ML model, no production credentials, no pre-existing Docker services.
Uses canonical synthetic events and the already-validated Stage B harness.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import stat
import subprocess
import time
import uuid
from pathlib import Path

from networkpulse.infra_event_harness import LabSettings, SyntheticIntegrityHarness

CONSENT = "I_ACCEPT_DISPOSABLE_STAGE_B_RESTART"
SCOPE = "ephemeral_single_node_non_ml_ci_process_sigkill_restart"


def require_disposable_ci(project: str, confirmed: bool) -> None:
    if not confirmed or os.getenv("NETWORKPULSE_STAGE_B_RESTART_CONFIRM") != CONSENT:
        raise ValueError("Explicit disposable Stage B restart consent required")
    if os.getenv("CI") != "true" or os.getenv("GITHUB_ACTIONS") != "true":
        raise ValueError("Only ephemeral GitHub Actions CI runner is authorized")
    if not re.fullmatch(r"npstageb-[0-9]{6,20}", project):
        raise ValueError("Unique scoped Stage B Compose project required")
    if os.getenv("DOCKER_HOST") or os.getenv("DOCKER_CONTEXT"):
        raise ValueError("Remote or overridden Docker context refused")
    try:
        mode = os.stat("/var/run/docker.sock").st_mode
    except OSError as exc:
        raise ValueError("Local Docker socket required") from exc
    if not stat.S_ISSOCK(mode):
        raise ValueError("Local Docker endpoint must be Unix socket")
    if _docker("context", "show") != "default":
        raise ValueError("Non-default Docker context refused")
    settings = LabSettings.from_env()
    if (settings.db_host, settings.db_port, settings.redis_host, settings.redis_port) != (
        "127.0.0.1", 15432, "127.0.0.1", 16379
    ):
        raise ValueError("Restart drill refuses non-CI loopback endpoints")


def _docker(*arguments: str, timeout: float = 45) -> str:
    """Never reveal Docker command arguments, container logs or stderr."""
    try:
        p = subprocess.run(
            ["docker", *arguments], capture_output=True, text=True,
            check=False, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Disposable Docker command unavailable") from exc
    if p.returncode:
        raise RuntimeError("Disposable Docker command failed")
    return p.stdout.strip()


def owned_container(project: str, service: str) -> str:
    """Ownership is validated before every destructive operation."""
    if service not in {"db", "redis"}:
        raise ValueError("Unsupported disposable service")
    container_id = _docker(
        "compose", "-p", project,
        "-f", "deploy/compose.infra-staging.yml",
        "-f", "deploy/compose.infra-stage-b.ci.yml",
        "ps", "-aq", service,
    )
    if not re.fullmatch(r"[0-9a-f]{64}", container_id):
        raise RuntimeError("Expected one owned Compose service container ID")
    obj = json.loads(_docker("inspect", container_id))
    if not isinstance(obj, list) or len(obj) != 1:
        raise ValueError("Invalid Docker ownership inspection response")
    item = obj[0]
    labels = item.get("Config", {}).get("Labels") or {}
    expected_image = {"db": "postgres:16-alpine", "redis": "redis:7-alpine"}[service]
    if (item.get("Id") != container_id
            or labels.get("com.docker.compose.project") != project
            or labels.get("com.docker.compose.service") != service
            or item.get("Config", {}).get("Image") != expected_image):
        raise ValueError("Container ownership/image check failed; refusing mutation")
    ports = (item.get("NetworkSettings") or {}).get("Ports") or {}
    port_name, host_port = {"db": ("5432/tcp", "15432"),
                            "redis": ("6379/tcp", "16379")}[service]
    bindings = ports.get(port_name)
    if (not isinstance(bindings, list) or len(bindings) != 1
            or bindings[0].get("HostIp") != "127.0.0.1"
            or bindings[0].get("HostPort") != host_port):
        raise ValueError("Container must expose only the expected CI loopback port")
    return container_id


def _port_down(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.35)
        return sock.connect_ex(("127.0.0.1", port)) != 0


def kill_and_recover(project: str, service: str, ready, *, during_down=None,
                     max_seconds=50) -> dict:
    container_id = owned_container(project, service)
    port = {"db": 15432, "redis": 16379}[service]
    begin = time.monotonic()
    _docker("kill", "--signal=KILL", container_id)
    # Reject a missing outage, including unexpected immediate auto-restart.
    verified_stopped = False
    for _ in range(20):
        item = json.loads(_docker("inspect", "--format", "{{json .State.Running}}", container_id))
        if item is False and _port_down(port):
            verified_stopped = True
            break
        time.sleep(0.1)
    if not verified_stopped:
        raise RuntimeError("Real isolated dependency stopped state not observed")
    if during_down is not None:
        during_down()
    _docker("start", container_id)
    if owned_container(project, service) != container_id:
        raise RuntimeError("Container identity changed unexpectedly during restart")
    deadline = time.monotonic() + max_seconds
    while time.monotonic() < deadline:
        try:
            if ready():
                return {
                    "service": service,
                    "stop_state_observed": True,
                    "same_container_restarted": True,
                    "restart_to_readiness_seconds": round(time.monotonic() - begin, 3),
                }
        except Exception:
            pass
        time.sleep(0.2)
    raise TimeoutError("Disposable dependency restart readiness deadline exceeded")


def _await_aof(cache) -> None:
    """Demand fsync acknowledgement before Redis crash."""
    acked = cache.execute_command("WAITAOF", 1, 0, 5000)
    if not isinstance(acked, (list, tuple)) or not acked or acked[0] != 1:
        raise RuntimeError("Redis local AOF fsync not acknowledged; crash drill blocked")


def run_drill(project: str) -> dict:
    settings = LabSettings.from_env()
    pg, cache = settings.connect()
    h = SyntheticIntegrityHarness(pg, cache, run_id=uuid.uuid4().hex, max_backlog=150)
    result = {"scope": SCOPE, "operational_acceptance": "NOT_CLAIMED",
              "run_id": h.run_id, "workload_kind": "synthetic_non_ml_only"}
    try:
        h.initialize_table()
        # Establish committed baseline records that a real SQL process kill must preserve.
        for ordinal in range(10):
            h.enqueue(ordinal)
        if h.drain() != 10:
            raise RuntimeError("Baseline durable events were not committed")
        for ordinal in range(10, 60):
            h.enqueue(ordinal)

        def verify_pg_outage():
            try:
                h.process_once()
            except RuntimeError as exc:
                if "pending failed deliveries" not in str(exc):
                    raise
            else:
                raise RuntimeError("Real PostgreSQL outage was not fail-closed")
            if (h.cache.xpending(h.stream, h.queue.group)["pending"] != 25
                    or h.cache.xlen(h.stream) != 50):
                raise RuntimeError("SQL outage lost or acknowledged uncommitted queue entries")

        old_pg = h.pg
        pg_restart = None
        try:
            pg_restart = kill_and_recover(
                project, "db", lambda: _postgres_probe(settings),
                during_down=verify_pg_outage,
            )
        finally:
            old_pg.close()
            h.pg = None
        h.pg = _postgres_connection(settings)
        if h.drain() != 50:
            raise RuntimeError("PostgreSQL restart did not drain all pending events")
        if not h.reconcile()["reconciled"]:
            raise RuntimeError("PostgreSQL crash recovery data integrity mismatch")
        result["postgres"] = pg_restart

        # Preserve 13 uncommitted consumer-group entries across real Redis SIGKILL.
        for ordinal in range(60, 110):
            h.enqueue(ordinal)
        preclaimed = h.queue._messages("stage-b-abandoned-worker", block_ms=5, count=13)
        if len(preclaimed) != 13:
            raise RuntimeError("Redis PEL crash precondition not established")
        _await_aof(cache)
        redis_restart = kill_and_recover(project, "redis", lambda: _redis_probe(settings))
        cache.close()
        cache = _redis_connection(settings)
        h.cache = cache
        h.queue.redis = cache
        after_pending = cache.xpending(h.stream, h.queue.group)["pending"]
        if after_pending != 13 or cache.xlen(h.stream) != 50:
            raise RuntimeError("Redis AOF restart lost pending/queued deliveries")
        if h.drain() != 50:
            raise RuntimeError("Redis restart did not drain pending/new messages")
        final = h.reconcile()
        if not final["reconciled"] or final["accepted_unique"] != 110:
            raise RuntimeError("Final SQL/Redis event reconciliation failed")
        if final["db_unique"] != 110 or final["redis_pending"] != 0:
            raise RuntimeError("Durable delivery count mismatch")
        result.update({"redis": redis_restart, "redis_pending_before_kill": 13,
                       "redis_pending_after_restart": after_pending,
                       "reconciliation": final, "status": "passed"})
        return result
    finally:
        try:
            if h.pg is not None:
                h.cleanup_synthetic_run()
        finally:
            if h.pg is not None:
                h.pg.close()
            cache.close()


def _postgres_connection(settings):
    import psycopg
    return psycopg.connect(
        host=settings.db_host, port=settings.db_port, dbname="networkpulse_staging_infra",
        user="networkpulse_staging", password=settings.db_password,
        connect_timeout=5, autocommit=True,
    )


def _redis_connection(settings):
    import redis
    return redis.Redis(
        host=settings.redis_host, port=settings.redis_port,
        password=settings.redis_password, decode_responses=True,
        socket_connect_timeout=4, socket_timeout=4, retry_on_timeout=False,
    )


def _postgres_probe(settings) -> bool:
    with _postgres_connection(settings) as conn, conn.cursor() as cur:
        cur.execute("SELECT current_database(), current_user")
        return cur.fetchone() == ("networkpulse_staging_infra", "networkpulse_staging")


def _redis_probe(settings) -> bool:
    with _redis_connection(settings) as client:
        return client.ping() is True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-disposable-ci", action="store_true")
    parser.add_argument("--project", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    require_disposable_ci(args.project, args.confirm_disposable_ci)
    if args.report.exists() or args.report.is_symlink():
        raise FileExistsError("Existing evidence may never be overwritten")
    if not args.report.parent.is_dir():
        raise ValueError("Report output directory must exist")
    try:
        result = run_drill(args.project)
    except Exception as exc:
        result = {"scope": SCOPE, "status": "failed", "operational_acceptance":
                  "NOT_CLAIMED", "failure_class": type(exc).__name__}
    with args.report.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"status": result["status"], "scope": SCOPE}))
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
