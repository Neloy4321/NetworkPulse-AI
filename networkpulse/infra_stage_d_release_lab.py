"""Stage D: fail-closed CI-only promotion, real container kill, and safe rollback.

This verifies a synthetic single-node release-switch control plane, not a real
signed model/image rollout or production release authorization.
"""
from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import stat
import subprocess
import time
from pathlib import Path

import httpx

from networkpulse.infra_stage_d_release_fixture import SCOPE, digest

CONSENT = "I_ACCEPT_DISPOSABLE_STAGE_D_ROLLBACK"
ENDPOINTS = {
    "stable": "http://127.0.0.1:18811",
    "candidate": "http://127.0.0.1:18812",
    "router": "http://127.0.0.1:18810",
}
COMPOSE = "deploy/compose.infra-stage-d.ci.yml"


def require_disposable_ci(project: str, route_dir: Path) -> None:
    if (os.getenv("CI") != "true" or os.getenv("GITHUB_ACTIONS") != "true"
            or os.getenv("NETWORKPULSE_STAGE_D_CONFIRM") != CONSENT):
        raise ValueError("Stage D requires explicit isolated GitHub CI consent")
    if not re.fullmatch(r"npstaged-[0-9]{6,20}", project):
        raise ValueError("Unique CI-only Stage D Compose project required")
    if os.getenv("DOCKER_HOST") or os.getenv("DOCKER_CONTEXT"):
        raise ValueError("External Docker daemon cannot be used")
    try:
        mode = os.stat("/var/run/docker.sock").st_mode
    except OSError as exc:
        raise ValueError("Local Docker socket required") from exc
    if not stat.S_ISSOCK(mode):
        raise ValueError("Local Docker Unix socket required")
    context = subprocess.run(["docker", "context", "show"], capture_output=True,
                             text=True, timeout=8, check=False)
    if context.returncode or context.stdout.strip() != "default":
        raise ValueError("Non-default Docker context is prohibited")
    parent = Path(os.environ.get("RUNNER_TEMP", "/nonexistent")).resolve()
    if (route_dir.is_symlink() or not route_dir.is_dir()
            or route_dir.resolve().parent != parent
            or stat.S_IMODE(route_dir.stat().st_mode) != 0o755):
        raise ValueError("Stage D route folder must be dedicated CI-only mode-0755 directory")
    active = route_dir / "active"
    if (not active.is_file() or active.is_symlink()
            or active.read_text(encoding="ascii") != "stable\n"):
        raise ValueError("Stage D must begin with a pinned stable route")
    if any(os.getenv(x) for x in ("NETWORKPULSE_STAGE_D_DEPLOY_TARGET",
                                  "NETWORKPULSE_PRODUCTION_URL")):
        raise ValueError("External production targets are forbidden")


def _docker(*args: str) -> str:
    try:
        result = subprocess.run(["docker", *args], capture_output=True,
                                text=True, check=False, timeout=35)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Isolated Docker operation unavailable") from exc
    if result.returncode:
        raise RuntimeError("Isolated Docker operation failed")
    return result.stdout.strip()


def owned_service(project: str, service: str) -> str:
    """Check exact project/service/image/host port before destructive kill."""
    if service != "candidate":
        raise ValueError("Only disposable candidate can be killed")
    ids = _docker("compose", "-p", project, "-f", COMPOSE, "ps", "-aq", service)
    if not re.fullmatch(r"[0-9a-f]{64}", ids):
        raise ValueError("Exactly one disposable candidate ID is required")
    data = json.loads(_docker("inspect", ids))
    if not isinstance(data, list) or len(data) != 1:
        raise ValueError("Unexpected docker inspect response")
    item = data[0]
    labels = item.get("Config", {}).get("Labels") or {}
    binds = (item.get("NetworkSettings") or {}).get("Ports", {}).get("8000/tcp")
    if (item.get("Id") != ids
            or item.get("Config", {}).get("Image") != "python:3.12-alpine"
            or labels.get("com.docker.compose.project") != project
            or labels.get("com.docker.compose.service") != service
            or not isinstance(binds, list) or len(binds) != 1
            or binds[0].get("HostIp") != "127.0.0.1"
            or binds[0].get("HostPort") != "18812"):
        raise ValueError("Candidate ownership or loopback-only port verification failed")
    return ids


def _until(label: str, condition, seconds: float = 30):
    start = time.monotonic()
    while time.monotonic() - start < seconds:
        try:
            item = condition()
            if item:
                return item
        except (httpx.HTTPError, ValueError, KeyError):
            pass
        time.sleep(0.25)
    raise RuntimeError("Stage D timed out: " + label)


def _verified_response(client: httpx.Client, role: str) -> dict:
    if role not in ENDPOINTS:
        raise ValueError("Unknown CI endpoint")
    response = client.get(ENDPOINTS[role] + "/release")
    response.raise_for_status()
    record = response.json()
    if (record.get("scope") != SCOPE or record.get("model_loaded") is not False
            or record.get("ready") is not True
            or record.get("release") not in {"stable", "candidate"}
            or record.get("sha256") != digest(record["release"])):
        raise ValueError("Release identity/digest preflight mismatch")
    if role != "router" and record["release"] != role:
        raise ValueError("Wrong release served by direct service")
    return record


def _preflight(client: httpx.Client, role: str, expected_sha256: str) -> dict:
    """Enforce the declared synthetic artifact fingerprint before promotion."""
    if role not in {"stable", "candidate"} or not re.fullmatch(
        r"[0-9a-f]{64}", expected_sha256
    ):
        raise ValueError("Invalid pinned synthetic release candidate")
    response = _verified_response(client, role)
    if not hmac.compare_digest(response["sha256"], expected_sha256):
        raise ValueError("Pinned release fingerprint mismatch; route unchanged")
    return response


def _switch(dir_path: Path, target: str, *, expected_previous: str) -> None:
    if target not in {"stable", "candidate"} or expected_previous not in (
        "stable", "candidate"
    ):
        raise ValueError("Invalid release transition")
    active = dir_path / "active"
    if active.is_symlink() or active.read_text(encoding="ascii") != expected_previous + "\n":
        raise RuntimeError("Unexpected active release; refusing promotion/rollback")
    temp = dir_path / (".route-" + target)
    if temp.exists() or temp.is_symlink():
        raise FileExistsError("Refusing overwrite of preexisting staged route")
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(target + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, active)
        dir_fd = os.open(dir_path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        temp.unlink(missing_ok=True)


def exercise(project: str, route_dir: Path) -> dict:
    with httpx.Client(timeout=2.0, trust_env=False) as client:
        stable = _until("stable dependency readiness", lambda:
                        _preflight(client, "stable", digest("stable")))
        candidate = _until("candidate dependency readiness", lambda:
                           _preflight(client, "candidate", digest("candidate")))
        _until("initial gateway stable", lambda:
               _verified_response(client, "router")["release"] == "stable")
        # Actual negative preflight, not a tautological boolean comparison.
        wrong_pin_rejected = False
        try:
            _preflight(client, "candidate", "0" * 64)
        except ValueError:
            wrong_pin_rejected = True
        if not wrong_pin_rejected:
            raise RuntimeError("Wrong candidate digest did not fail closed")
        if (route_dir / "active").read_text(encoding="ascii") != "stable\n":
            raise RuntimeError("Dry-run changed stable route")
        started = time.monotonic()
        _switch(route_dir, "candidate", expected_previous="stable")
        _until("candidate routed", lambda:
               _verified_response(client, "router")["release"] == "candidate")
        promoted = round(time.monotonic() - started, 3)

        container_id = owned_service(project, "candidate")
        _docker("kill", "--signal=KILL", container_id)
        last_gateway_status = "not_observed"

        def outage_probe():
            nonlocal last_gateway_status
            try:
                response = client.get(ENDPOINTS["router"] + "/release")
            except httpx.HTTPError:
                last_gateway_status = "transport_error"
                return False
            last_gateway_status = str(response.status_code)
            return response.status_code == 503

        try:
            _until("actual candidate outage", outage_probe)
        except RuntimeError as exc:
            if "Stage D timed out: actual candidate outage" not in str(exc):
                raise
            raise RuntimeError(
                "Stage D timed out: actual candidate outage "
                "(gateway_http=" + last_gateway_status + ")"
            ) from exc
        if client.get(ENDPOINTS["stable"] + "/release").status_code != 200:
            raise RuntimeError("Stable route backup unavailable during failure")
        begin = time.monotonic()
        _switch(route_dir, "stable", expected_previous="candidate")
        verified = _until("healthy stable rollback", lambda:
                          _verified_response(client, "router"))
        if verified["release"] != "stable" or verified["sha256"] != stable["sha256"]:
            raise RuntimeError("Rollback target identity was not restored")
        rolled_back = round(time.monotonic() - begin, 3)
        # A second genuine preflight must fail while the candidate is dead.
        repromotion_blocked = False
        try:
            _preflight(client, "candidate", candidate["sha256"])
        except (httpx.HTTPError, ValueError):
            repromotion_blocked = True
        if not repromotion_blocked:
            raise RuntimeError("Killed candidate unexpectedly passed promotion preflight")
        if (route_dir / "active").read_text(encoding="ascii") != "stable\n":
            raise RuntimeError("Rollback did not persist stable route")
        return {
            "status": "passed", "scope": SCOPE,
            "operational_acceptance": "NOT_CLAIMED",
            "production_release": "NOT_ATTEMPTED",
            "model_acceptance": "NOT_CLAIMED",
            "stable_digest": stable["sha256"],
            "candidate_digest": candidate["sha256"],
            "preflight_wrong_pin_rejected": wrong_pin_rejected,
            "candidate_promotion_verified": True,
            "real_owned_candidate_sigkill": True,
            "gateway_failure_detected": True,
            "stable_service_survived": True,
            "rollback_restored_pinned_stable": True,
            "dead_candidate_repomotion_blocked": repromotion_blocked,
            "promotion_observed_seconds": promoted,
            "rollback_observed_seconds": rolled_back,
            "final_release": "stable",
            "image_digest_provenance": "NOT_VERIFIED",
            "external_deployment": "NOT_TESTED",
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--route-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    require_disposable_ci(args.project, args.route_dir)
    if args.report.exists() or args.report.is_symlink():
        raise FileExistsError("Existing Stage D evidence must not be overwritten")
    try:
        result = exercise(args.project, args.route_dir)
    except Exception as exc:
        result = {"status": "failed", "scope": SCOPE,
                  "failure_class": type(exc).__name__,
                  "operational_acceptance": "NOT_CLAIMED"}
        # Only hardcoded CI phase labels are safe to emit into public CI logs.
        reason = str(exc)
        if type(exc) is RuntimeError and reason.startswith("Stage D timed out: "):
            result["failed_check"] = reason[:140]
    with args.report.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"status": result["status"], "scope": SCOPE}))
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
