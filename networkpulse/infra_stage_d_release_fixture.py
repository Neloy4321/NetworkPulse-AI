"""Stage D non-ML disposable release-switch fixture; never a production router.

Simulates stable/candidate services and one explicit route pointer inside a
single isolated CI Docker Compose project. No model, external sensor or API key.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import socket
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SCOPE = "ephemeral_nonml_stage_d_ci"
ROLES = {"stable", "candidate", "router"}


def digest(role: str) -> str:
    if role not in {"stable", "candidate"}:
        raise ValueError("Unknown synthetic release")
    return hashlib.sha256(("networkpulse-stage-d-fixture:" + role + ":v1").encode()).hexdigest()


def route_target(path: Path) -> str:
    value = path.read_text(encoding="ascii").strip()
    if value not in {"stable", "candidate"}:
        raise ValueError("Unknown synthetic release route; fail closed")
    return value


def resolve_private_ci_upstream(name: str, cache: dict[str, str], *, resolver=None) -> str:
    """Cache an already-alive container's private IP; never re-resolve after kill.

    Docker embedded DNS can stall once a container exits; a cached, preflighted
    private endpoint guarantees the failure probe has a bounded connection path.
    """
    if name not in {"stable", "candidate"}:
        raise ValueError("Unknown synthetic release host")
    if name not in cache:
        raw = (resolver or socket.gethostbyname)(name)
        try:
            ip = ipaddress.IPv4Address(raw)
        except ipaddress.AddressValueError as exc:
            raise ValueError("Invalid CI upstream address") from exc
        if not ip.is_private or ip.is_loopback or ip.is_unspecified:
            raise ValueError("Refusing any non-private Docker upstream")
        cache[name] = str(ip)
    return cache[name]


def make_handler(role: str, route_file: Path | None = None):
    if role not in ROLES:
        raise ValueError("Invalid CI fixture role")

    ci_ip_cache: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return

        def _send(self, code: int, result: dict):
            data = json.dumps(result, sort_keys=True).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path not in {"/health/ready", "/release"}:
                self._send(404, {"error": "unknown_test_endpoint"})
                return
            if role != "router":
                self._send(200, {
                    "scope": SCOPE, "model_loaded": False,
                    "release": role, "sha256": digest(role), "ready": True,
                })
                return
            try:
                if route_file is None:
                    raise ValueError("No route file provided")
                active = route_target(route_file)
                upstream_ip = resolve_private_ci_upstream(active, ci_ip_cache)
                request = urllib.request.Request(
                    f"http://{upstream_ip}:8000{self.path}",
                    method="GET", headers={"Accept": "application/json"},
                )
                with urllib.request.urlopen(request, timeout=1.0) as r:
                    if r.status != 200:
                        raise ValueError("Unhealthy upstream response")
                    record = json.load(r)
                if (record.get("scope") != SCOPE or record.get("model_loaded") is not False
                        or record.get("release") != active
                        or record.get("sha256") != digest(active)
                        or record.get("ready") is not True):
                    raise ValueError("Upstream identity is not pinned")
                self._send(200, record)
            except (ValueError, OSError, urllib.error.URLError, json.JSONDecodeError):
                self._send(503, {"error": "route_unavailable", "scope": SCOPE})

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True, choices=sorted(ROLES))
    parser.add_argument("--route-file", type=Path)
    args = parser.parse_args()
    if args.role == "router" and args.route_file is None:
        parser.error("router requires its isolated route file")
    if os.getenv("NETWORKPULSE_STAGE_D_MODE") != SCOPE:
        raise SystemExit("Refusing non-disposable Stage D service mode")
    with ThreadingHTTPServer(("0.0.0.0", 8000),
                             make_handler(args.role, args.route_file)) as server:
        server.serve_forever(poll_interval=0.2)


if __name__ == "__main__":
    main()
