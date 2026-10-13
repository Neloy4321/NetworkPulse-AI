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
