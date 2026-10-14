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
