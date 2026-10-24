"""Isolated local demo acceptance. It does not certify real-world IDS performance."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import platform
import secrets
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from networkpulse.api import create_app
from networkpulse.cli import main as cli_main
from networkpulse.config import Settings
from networkpulse.migrations import upgrade_database
from networkpulse.simulator import sample_flows


@contextlib.contextmanager
def _isolated_environment(overrides: dict[str, str]):
    original = {name: os.environ.get(name) for name in overrides}
    try:
        os.environ.update(overrides)
        yield
    finally:
        for name, value in original.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _bootstrap(count: int = 160, seed: int = 7) -> dict:
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        code = cli_main(["bootstrap", "--count", str(count), "--seed", str(seed)])
    if code != 0:
        raise RuntimeError("Synthetic bootstrap did not complete successfully")
    return json.loads(captured.getvalue())


def _git_head() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], check=False, capture_output=True, text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "unknown"


def run_acceptance() -> dict:
    """Exercise a private, disposable SQLite + synthetic model + in-process API."""
    checks: dict[str, str] = {}

    def require(name: str, condition: bool):
        checks[name] = "PASS" if condition else "FAIL"
        if not condition:
            raise AssertionError(f"Local demo gate failed: {name}")

    with tempfile.TemporaryDirectory(prefix="networkpulse-local-demo-") as directory:
        sandbox = Path(directory)
        model_path = sandbox / "synthetic-model.joblib"
        database_url = "sqlite:///" + str(sandbox / "synthetic.sqlite")
        api_key = secrets.token_urlsafe(32)
        overrides = {
            "DATABASE_URL": database_url,
            "MODEL_PATH": str(model_path),
            "NETWORKPULSE_API_KEY": api_key,
            "NETWORKPULSE_AUTH_MODE": "local",
            "NETWORKPULSE_DEPLOYMENT": "development",
            "NETWORKPULSE_BROWSER_OIDC": "false",
            "NETWORKPULSE_SECURITY_REDIS_URL": "",
            "MODEL_SHA256": "",
            "REDIS_METRICS_URL": "",
        }
        with _isolated_environment(overrides):
            migration = upgrade_database(database_url)
            require("isolated_database_migration", migration.get("ready") is True)
            first = _bootstrap()
            second = _bootstrap()
            inserted = first["bootstrap"].get("inserted", 0)
            require("synthetic_model_created", model_path.is_file())
            require(
                "repeatable_bootstrap_idempotency",
                inserted == 40 and second["bootstrap"].get("inserted") == 0
                and second["bootstrap"].get("duplicates") == inserted,
            )
            require(
                "model_explicitly_marked_synthetic",
                "synthetic" in str(first["model"].get("source", "")).lower(),
            )
            settings = Settings(
                database_url=database_url, model_path=model_path, api_key=api_key,
            )
            with TestClient(create_app(settings)) as client:
                require(
                    "api_liveness_and_readiness",
                    client.get("/health/live").status_code == 200
                    and client.get("/health/ready").status_code == 200,
                )
                page = client.get("/")
                require(
                    "dashboard_and_local_assets",
                    page.status_code == 200 and "NETWORKPULSE" in page.text
                    and client.get("/static/app.js").status_code == 200,
                )
                model = client.get("/api/v1/model")
                require(
                    "loaded_model_provenance",
                    model.status_code == 200
                    and "synthetic" in str(model.json().get("source", "")).lower(),
                )
                event = sample_flows(120, seed=9301)[-1].model_dump(mode="json")
                payload = {"events": [event]}
                require(
                    "anonymous_mutation_rejected",
                    client.post("/api/v1/ingest", json=payload).status_code == 401,
                )
                accepted = client.post(
                    "/api/v1/ingest", json=payload, headers={"X-API-Key": api_key},
                )
                require(
                    "authenticated_inference_and_ingestion",
                    accepted.status_code == 200
                    and accepted.json().get("inserted") == 1,
                )
                summary = client.get("/api/v1/summary")
                require(
                    "persisted_summary_readable",
                    summary.status_code == 200
                    and summary.json().get("flows") == inserted + 1,
                )
            digest = hashlib.sha256(model_path.read_bytes()).hexdigest()

    return {
        "schema_version": 1,
        "scope": "LOCAL_SYNTHETIC_PORTFOLIO_DEMO",
        "local_demo_engineering": "PASS",
        "independent_ml_generalization": "NOT_ACCEPTED",
        "production_or_live_network_acceptance": "NOT_ACCEPTED",
        "note": (
            "This ephemeral synthetic model is not the frozen IoT-SFC/UWF research model. "
            "Previous independent-source recall failure is not waived."
        ),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "git_head": _git_head(),
        "python": platform.python_version(),
        "synthetic_model_sha256": digest,
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="Optional NEW JSON evidence path")
    args = parser.parse_args()
    if args.report is not None and args.report.exists():
        parser.error("Report already exists; choose a new evidence filename")
    try:
        report = run_acceptance()
    except Exception as exc:
        report = {
            "schema_version": 1,
            "scope": "LOCAL_SYNTHETIC_PORTFOLIO_DEMO",
            "local_demo_engineering": "FAIL",
            "independent_ml_generalization": "NOT_ACCEPTED",
            "production_or_live_network_acceptance": "NOT_ACCEPTED",
            "error": f"{type(exc).__name__}: {exc}",
        }
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    print(encoded, end="")
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with args.report.open("x", encoding="utf-8") as handle:
            handle.write(encoded)
    return 0 if report["local_demo_engineering"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
