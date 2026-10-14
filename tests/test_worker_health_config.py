"""Compose worker liveness must not reuse the API-only HTTP probe."""

from pathlib import Path


def test_worker_compose_uses_redis_specific_healthcheck():
    compose = Path("compose.yaml").read_text(encoding="utf-8")
    worker_section = compose.split("  worker:\n", 1)[1].split("\n  api:\n", 1)[0]

    assert "healthcheck:" in worker_section
    assert "redis.Redis.from_url" in worker_section
    assert "REDIS_URL" in worker_section
    assert "socket_connect_timeout=2" in worker_section
    assert "/health/ready" not in worker_section
    assert "condition: service_healthy" in worker_section


def test_analytics_workers_have_success_cycle_healthchecks():
    compose = Path("compose.yaml").read_text(encoding="utf-8")
    mlops = compose.split("  mlops-worker:\n", 1)[1].split("  behavior-worker:\n", 1)[0]
    behavior = compose.split("  behavior-worker:\n", 1)[1].split("  api:\n", 1)[0]
    for section, role in ((mlops, "mlops"), (behavior, "behavior")):
        assert "networkpulse.ops_health" in section
        assert "--max-age-seconds" in section
        assert '"--role", "' + role + '"' in section
        assert "healthcheck:" in section
        assert "disable: true" not in section
        assert "stop_grace_period" in section
    assert 'model_data:/app/data:ro' in mlops


def test_stream_worker_health_requires_recent_successful_cycle():
    compose = Path("compose.yaml").read_text(encoding="utf-8")
    worker = compose.split("  worker:\n", 1)[1].split("\n  mlops-worker:\n", 1)[0]
    assert "networkpulse.ops_health --role stream" in worker
    assert "--max-age-seconds 120" in worker
    assert "model_data:/app/data:ro" in worker
    assert "restart: unless-stopped" in worker
    assert "stop_grace_period: 30s" in worker
    assert "socket_connect_timeout=2" in worker


def test_worker_exporter_is_private_and_scraped_by_prometheus():
    compose = Path("compose.yaml").read_text(encoding="utf-8")
    worker = compose.split("  worker:\n", 1)[1].split("\n  mlops-worker:\n", 1)[0]
    assert 'NETWORKPULSE_WORKER_METRICS_PORT: "9101"' in worker
    assert "ports:" not in worker
    assert "networks: [internal]" in worker
    config = Path("infra/prometheus/prometheus.yaml").read_text(encoding="utf-8")
    assert "networkpulse-worker" in config
    assert "worker:9101" in config
    rules = Path("infra/prometheus/alerts.yml").read_text(encoding="utf-8")
    assert "NetworkPulseWorkerDegraded" in rules
    assert "NetworkPulseWorkerQueueP95High" in rules


def test_cli_defers_worker_group_creation_until_release_preflight():
    cli = Path("networkpulse/cli.py").read_text(encoding="utf-8")
    segment = cli.split('if args.command in {"collect", "worker"}:', 1)[1]
    assert "signal.SIGTERM" in segment
    assert "stop_requested=stopping.is_set" in segment
    # Only collector initializes immediately. Worker preflights model release
    # before creating a group via process_events().
    collector = segment.split("else:\n                queue.initialize()", 1)
    assert len(collector) == 2
