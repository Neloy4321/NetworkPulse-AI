"""Ephemeral, isolated Stage C synthetic metrics and authenticated webhook receiver.

No IDS, real sensors, production paging, credentials, or external traffic data.
The only control/acknowledgment is a CI-only simulation, NOT human on-call ACK.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

EXPECTED_ALERTS = {
    "NetworkPulseCISyntheticDependencyFailure",
    "NetworkPulseCISyntheticMutedProbe",
}
SCOPE = "disposable-stage-c-ci"


class FixtureState:
    def __init__(self, token: str):
        if len(token) < 32:
            raise ValueError("CI alert test token is missing or short")
        self.token = token
        self.lock = threading.Lock()
        self.dependency_up = True
        self.muted_probe = False
        self.receipts: list[dict] = []
        self.acknowledgments: dict[str, dict] = {}

    def authorized(self, header: str) -> bool:
        return hmac.compare_digest(header, "Bearer " + self.token)

    def set_signal(self, signal: str, enabled: bool) -> None:
        if signal not in ("dependency_up", "muted_probe") or type(enabled) is not bool:
            raise ValueError("Only canonical synthetic signals are accepted")
        with self.lock:
            setattr(self, signal, enabled)

    def metrics(self) -> bytes:
        with self.lock:
            dependency = int(self.dependency_up)
            muted = int(self.muted_probe)
        return (
            "# TYPE networkpulse_ci_synthetic_dependency_up gauge\n"
            f'networkpulse_ci_synthetic_dependency_up{{scope="{SCOPE}"}} {dependency}\n'
            "# TYPE networkpulse_ci_synthetic_muted_probe gauge\n"
            f'networkpulse_ci_synthetic_muted_probe{{scope="{SCOPE}"}} {muted}\n'
        ).encode("ascii")

    def receive(self, payload: dict) -> int:
        if not isinstance(payload, dict) or payload.get("version") != "4":
            raise ValueError("Unsupported Alertmanager webhook payload")
        if payload.get("status") not in ("firing", "resolved"):
            raise ValueError("Unsupported Alertmanager notification status")
        alerts = payload.get("alerts")
        if not isinstance(alerts, list) or not 1 <= len(alerts) <= 10:
            raise ValueError("Invalid webhook alert count")
        receipts = []
        for alert in alerts:
            if not isinstance(alert, dict) or not isinstance(alert.get("labels"), dict):
                raise ValueError("Invalid alert labels")
            labels = alert["labels"]
            fingerprint = alert.get("fingerprint")
            if (labels.get("alertname") not in EXPECTED_ALERTS
                    or labels.get("scope") != SCOPE
                    or not isinstance(fingerprint, str)
                    or not re.fullmatch(r"[0-9a-fA-F]{8,64}", fingerprint)
                    or alert.get("status") not in ("firing", "resolved")):
                raise ValueError("Foreign or malformed CI alert notification")
            receipts.append({
                "alertname": labels["alertname"],
                "scope": SCOPE,
                "status": alert["status"],
                "fingerprint": fingerprint,
                "received_monotonic": round(time.monotonic(), 6),
            })
        with self.lock:
            self.receipts.extend(receipts)
        return len(receipts)

    def acknowledge(self, fingerprint: str) -> tuple[dict, bool]:
        if not isinstance(fingerprint, str) or not re.fullmatch(
            r"[0-9a-fA-F]{8,64}", fingerprint
        ):
            raise ValueError("Invalid synthetic alert fingerprint")
        with self.lock:
            if not any(
                entry["fingerprint"] == fingerprint and entry["status"] == "firing"
                for entry in self.receipts
            ):
                raise LookupError("Cannot acknowledge undelivered/nonfiring alert")
            prior = self.acknowledgments.get(fingerprint)
            if prior is not None:
                return dict(prior), False
            record = {
                "fingerprint": fingerprint,
                "kind": "synthetic_ci_ack_only_not_human",
                "recorded_monotonic": round(time.monotonic(), 6),
            }
            self.acknowledgments[fingerprint] = record
            return dict(record), True

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "scope": SCOPE,
                "dependency_up": self.dependency_up,
                "muted_probe": self.muted_probe,
                "receipts": [dict(item) for item in self.receipts],
                "acknowledgments": list(self.acknowledgments.values()),
            }


def make_handler(state: FixtureState):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            # Never print authorization headers, webhook payloads or tokens.
            return

        def _reply(self, code: int, payload: dict, *, content_type="application/json"):
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _allowed(self) -> bool:
            if not state.authorized(self.headers.get("Authorization", "")):
                self._reply(401, {"error": "authentication_required"})
                return False
            return True

        def _input(self) -> dict:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536:
                raise ValueError("Request size out of bounds")
            parsed = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError("Object required")
            return parsed

        def do_GET(self):
            if self.path == "/health":
                self._reply(200, {"status": "live", "scope": SCOPE})
                return
            if self.path == "/metrics":
                data = state.metrics()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            if self.path == "/observations":
                if self._allowed():
                    self._reply(200, state.snapshot())
                return
            self._reply(404, {"error": "not_found"})

        def do_POST(self):
            if self.path not in ("/control", "/webhook", "/ack"):
                self._reply(404, {"error": "not_found"})
                return
            if not self._allowed():
                return
            try:
                data = self._input()
                if self.path == "/control":
                    if set(data) != {"signal", "enabled"}:
                        raise ValueError("Only synthetic signal control permitted")
                    state.set_signal(data["signal"], data["enabled"])
                    self._reply(200, {"accepted": True, "scope": SCOPE})
                elif self.path == "/webhook":
                    count = state.receive(data)
                    self._reply(200, {"accepted_alerts": count, "scope": SCOPE})
                else:
                    if set(data) != {"fingerprint"}:
                        raise ValueError("Only synthetic fingerprint ACK permitted")
                    record, created = state.acknowledge(data["fingerprint"])
                    self._reply(200, {"ack": record, "created": created})
            except (ValueError, KeyError, json.JSONDecodeError):
                self._reply(400, {"error": "invalid_synthetic_input"})
            except LookupError:
                self._reply(404, {"error": "firing_delivery_not_found"})

    return Handler


def main():
    secret = Path(os.environ.get("NETWORKPULSE_STAGE_C_TOKEN_FILE", "/no-token"))
    token = secret.read_text(encoding="ascii").strip()
    server = ThreadingHTTPServer(("0.0.0.0", 8080), make_handler(FixtureState(token)))
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
