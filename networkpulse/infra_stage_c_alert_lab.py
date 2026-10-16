"""End-to-end Stage C CI probe: real Prometheus -> Alertmanager -> webhook.

Explicitly NOT a production operator paging test. No ML or real network data.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from networkpulse.infra_stage_c_alert_fixture import SCOPE

CONSENT = "I_ACCEPT_DISPOSABLE_STAGE_C_ALERTS"
FAILURE = "NetworkPulseCISyntheticDependencyFailure"
MUTED = "NetworkPulseCISyntheticMutedProbe"
FIXTURE = "http://127.0.0.1:19871"
PROMETHEUS = "http://127.0.0.1:19090"
ALERTMANAGER = "http://127.0.0.1:19093"


def require_disposable_ci(project: str) -> None:
    if (os.getenv("CI") != "true" or os.getenv("GITHUB_ACTIONS") != "true"
            or os.getenv("NETWORKPULSE_STAGE_C_CONFIRM") != CONSENT):
        raise ValueError("Stage C is allowed only with explicit disposable GitHub CI consent")
    if not re.fullmatch(r"npstagec-[0-9]{6,20}", project):
        raise ValueError("Unique isolated Stage C Compose project required")
    if os.getenv("DOCKER_HOST") or os.getenv("DOCKER_CONTEXT"):
        raise ValueError("External Docker daemon/context is forbidden")
    try:
        if not stat.S_ISSOCK(os.stat("/var/run/docker.sock").st_mode):
            raise ValueError("Local Docker socket required")
    except OSError as exc:
        raise ValueError("Local Docker socket required") from exc
    result = subprocess.run(
        ["docker", "context", "show"], text=True, capture_output=True,
        check=False, timeout=8,
    )
    if result.returncode or result.stdout.strip() != "default":
        raise ValueError("Nondefault Docker context refused")
    token = os.getenv("NETWORKPULSE_STAGE_C_TEST_TOKEN", "")
    if not re.fullmatch(r"[0-9a-fA-F]{48,128}", token):
        raise ValueError("Ephemeral Stage C bearer token missing or invalid")
    # Do not allow network-accessible sender/receiver URLs or operator customization.
    if any(os.getenv(name) for name in (
        "NETWORKPULSE_STAGE_C_ENDPOINT", "NETWORKPULSE_PRODUCTION_URL",
    )):
        raise ValueError("Cannot override disposable loopback targets")


def _until(label: str, callback, *, seconds: float = 45):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        try:
            answer = callback()
            if answer:
                return answer
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            last = type(exc).__name__
        time.sleep(0.4)
    raise RuntimeError(f"Stage C timed out waiting for {label} ({last or 'no condition'})")


def _api(client: httpx.Client, method: str, url: str, **kwargs):
    response = client.request(method, url, **kwargs)
    response.raise_for_status()
    return response.json() if response.content else {}


def _receipts(client: httpx.Client, token: str) -> list[dict]:
    result = _api(client, "GET", FIXTURE + "/observations",
                  headers={"Authorization": "Bearer " + token})
    if result.get("scope") != SCOPE:
        raise RuntimeError("Foreign CI fixture observations")
    return result["receipts"]


def _send_signal(client: httpx.Client, token: str, name: str, enabled: bool):
    result = _api(client, "POST", FIXTURE + "/control",
                  headers={"Authorization": "Bearer " + token},
                  json={"signal": name, "enabled": enabled})
    if result != {"accepted": True, "scope": SCOPE}:
        raise RuntimeError("Synthetic signal was not accepted")


def _prometheus_firing(client: httpx.Client, alertname: str) -> bool:
    result = _api(client, "GET", PROMETHEUS + "/api/v1/alerts")
    return any(
        a.get("labels", {}).get("alertname") == alertname
        and a.get("labels", {}).get("scope") == SCOPE
        and a.get("state") == "firing"
        for a in result.get("data", {}).get("alerts", [])
    )


def _webhook(client: httpx.Client, token: str, alertname: str,
             status: str, fingerprint: str | None = None):
    return next(
        (r for r in _receipts(client, token)
         if r["alertname"] == alertname and r["status"] == status
         and (fingerprint is None or r["fingerprint"] == fingerprint)),
        None,
    )


def _fmt(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


def _silence(client: httpx.Client) -> str:
    now = datetime.now(timezone.utc)
    body = {
        "matchers": [
            {"name": "alertname", "value": MUTED, "isRegex": False, "isEqual": True},
            {"name": "scope", "value": SCOPE, "isRegex": False, "isEqual": True},
        ],
        "startsAt": _fmt(now - timedelta(seconds=5)),
        "endsAt": _fmt(now + timedelta(minutes=2)),
        "createdBy": "nonml-disposable-ci",
        "comment": "Synthetic CI-only silence acceptance probe; not a human ACK",
    }
    result = _api(client, "POST", ALERTMANAGER + "/api/v2/silences", json=body)
    silence_id = result.get("silenceID")
    if not isinstance(silence_id, str) or not silence_id:
        raise RuntimeError("Alertmanager did not create a silence")
    return silence_id


def _silenced_in_alertmanager(client: httpx.Client, silence_id: str) -> bool:
    alerts = _api(client, "GET", ALERTMANAGER + "/api/v2/alerts",
                  params={"active": "true", "silenced": "true",
                          "inhibited": "true", "unprocessed": "true"})
    return any(
        item.get("labels", {}).get("alertname") == MUTED
        and item.get("labels", {}).get("scope") == SCOPE
        and silence_id in item.get("status", {}).get("silencedBy", [])
        for item in alerts
    )


def run_drill() -> dict:
    token = os.environ["NETWORKPULSE_STAGE_C_TEST_TOKEN"]
    headers = {"Authorization": "Bearer " + token}
    created_silence = None
    with httpx.Client(timeout=4.0) as client:
        try:
            _until("Prometheus and Alertmanager health", lambda: (
                client.get(PROMETHEUS + "/-/ready").status_code == 200
                and client.get(ALERTMANAGER + "/-/ready").status_code == 200
                and client.get(FIXTURE + "/health").status_code == 200
            ), seconds=65)
            _until("real scrape target UP", lambda: any(
                t.get("health") == "up" and
                t.get("labels", {}).get("job") == "networkpulse-stage-c-fixture"
                for t in _api(client, "GET", PROMETHEUS + "/api/v1/targets")
                .get("data", {}).get("activeTargets", [])
            ), seconds=40)
            # Auth is enforced even on isolated loopback; no human ACK is implied.
            anonymous = client.get(FIXTURE + "/observations")
            if anonymous.status_code != 401:
                raise RuntimeError("Unauthenticated webhook ledger read was allowed")
            forbidden = client.post(FIXTURE + "/ack",
                                    json={"fingerprint": "a" * 16})
            if forbidden.status_code != 401:
                raise RuntimeError("Unauthenticated acknowledgment was allowed")
            forged_webhook = client.post(
                FIXTURE + "/webhook", json={"version": "4", "alerts": []}
            )
            if forged_webhook.status_code != 401:
                raise RuntimeError("Unauthenticated fake webhook was accepted")

            started = time.monotonic()
            _send_signal(client, token, "dependency_up", False)
            _until("Prometheus synthetic dependency alert firing",
                   lambda: _prometheus_firing(client, FAILURE))
            receipt = _until("Alertmanager authenticated firing webhook",
                             lambda: _webhook(client, token, FAILURE, "firing"))
            fire_latency = round(time.monotonic() - started, 3)
            fingerprint = receipt["fingerprint"]
            ack = _api(client, "POST", FIXTURE + "/ack",
                       headers=headers, json={"fingerprint": fingerprint})
            if (ack.get("created") is not True
                    or ack.get("ack", {}).get("kind")
                    != "synthetic_ci_ack_only_not_human"):
                raise RuntimeError("Synthetic acknowledgment ledger refused new ACK")
            repeat_ack = _api(client, "POST", FIXTURE + "/ack",
                              headers=headers, json={"fingerprint": fingerprint})
            if repeat_ack.get("created") is not False:
                raise RuntimeError("Synthetic ACK was not idempotent")

            resolved_start = time.monotonic()
            _send_signal(client, token, "dependency_up", True)
            _until("Alertmanager authenticated resolved webhook", lambda: _webhook(
                client, token, FAILURE, "resolved", fingerprint,
            ), seconds=50)
            resolved_latency = round(time.monotonic() - resolved_start, 3)

            created_silence = _silence(client)
            _until("Alertmanager silence becomes active", lambda: _api(
                client, "GET", ALERTMANAGER + "/api/v2/silence/" + created_silence
            ).get("status", {}).get("state") == "active")
            _send_signal(client, token, "muted_probe", True)
            _until("Prometheus muted synthetic alert firing", lambda:
                   _prometheus_firing(client, MUTED))
            _until("Alertmanager confirms silence has suppressed firing alert",
                   lambda: _silenced_in_alertmanager(client, created_silence))
            # Multiple group_wait intervals: no webhook must be emitted while
            # real Alertmanager reports a matching, active silence.
            time.sleep(5)
            if _webhook(client, token, MUTED, "firing") is not None:
                raise RuntimeError("Silenced alert unexpectedly reached the webhook")
            _api(client, "DELETE",
                 ALERTMANAGER + "/api/v2/silence/" + created_silence)
            created_silence = None
            _until("new webhook after silence expiration", lambda:
                   _webhook(client, token, MUTED, "firing"), seconds=50)
            _send_signal(client, token, "muted_probe", False)
            _until("resolved webhook after muted probe recovery", lambda:
                   _webhook(client, token, MUTED, "resolved"), seconds=50)
            observed = _receipts(client, token)
            ack_snapshot = _api(client, "GET", FIXTURE + "/observations",
                                headers=headers)["acknowledgments"]
            if len(ack_snapshot) != 1 or len(observed) < 4:
                raise RuntimeError("Notification or synthetic ACK evidence is incomplete")
            return {
                "status": "passed", "scope": "ephemeral_ci_nonml_real_alert_pipeline",
                "operational_acceptance": "NOT_CLAIMED",
                "human_acknowledgment": "NOT_TESTED",
                "real_external_paging": "NOT_TESTED",
                "prometheus_alert_fired": True,
                "alertmanager_firing_webhook_delivered": True,
                "resolved_webhook_delivered": True,
                "webhook_bearer_auth_enforced": True,
                "unauthenticated_ack_rejected": True,
                "synthetic_ack_recorded": True,
                "synthetic_ack_idempotent": True,
                "alertmanager_silence_verified": True,
                "webhook_suppressed_while_silenced": True,
                "delivery_resumed_after_silence": True,
                "firing_to_receipt_observed_seconds": fire_latency,
                "recovery_to_resolved_receipt_observed_seconds": resolved_latency,
                "delivered_notification_records": len(observed),
                "oncall_slo": "NOT_CLAIMED",
            }
        finally:
            # Always clear synthetic sources and attempt to expire test silence.
            for name, value in (("dependency_up", True), ("muted_probe", False)):
                try:
                    _send_signal(client, token, name, value)
                except httpx.HTTPError:
                    pass
            if created_silence:
                try:
                    client.delete(ALERTMANAGER + "/api/v2/silence/" + created_silence)
                except httpx.HTTPError:
                    pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    require_disposable_ci(args.project)
    if args.report.exists() or args.report.is_symlink():
        raise FileExistsError("Stage C report already exists; refusing overwrite")
    try:
        outcome = run_drill()
    except Exception as exc:
        outcome = {
            "status": "failed", "scope": "ephemeral_ci_nonml_real_alert_pipeline",
            "failure_class": type(exc).__name__,
            "operational_acceptance": "NOT_CLAIMED",
        }
    with args.report.open("x", encoding="utf-8") as output:
        json.dump(outcome, output, sort_keys=True, indent=2)
        output.write("\n")
    print(json.dumps({"status": outcome["status"], "scope": outcome["scope"]}))
    return 0 if outcome["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
