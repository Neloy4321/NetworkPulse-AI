"""Security regression tests: bounded admission and responses."""
from networkpulse.security.limits import MutationLimiter


def test_rate_limiter_fails_closed_when_many_active_peers():
    limiter = MutationLimiter(per_minute=2, max_peers=10)
    for i in range(10):
        assert limiter.admit(f"peer-{i}", now=1)
    assert not limiter.admit("new-peer", now=2)
    assert len(limiter.buckets) == 10
    assert limiter.admit("peer-0", now=3)
    assert not limiter.admit("peer-0", now=4)
    assert not limiter.admit("new-peer", now=5)
    assert limiter.admit("new-peer", now=62)
    assert len(limiter.buckets) <= 10


def test_security_headers_on_success_and_early_rejections(client, app_settings):
    page = client.get("/")
    assert page.status_code == 200
    assert page.headers["x-frame-options"] == "DENY"
    assert page.headers["content-security-policy"].startswith("default-src 'self'")
    assert page.headers["cache-control"] == "no-store"
    assert page.headers["permissions-policy"]
    batch = {"events": []}
    unauthorized = client.post("/api/v1/ingest", json=batch)
    assert unauthorized.status_code == 401
    assert unauthorized.headers["x-frame-options"] == "DENY"
    malformed = client.post("/api/v1/ingest", headers={
        "Content-Length": "-1", "X-API-Key": app_settings.api_key
    }, content=b"x")
    assert malformed.status_code == 413
    assert malformed.headers["x-frame-options"] == "DENY"
    assert malformed.headers["cache-control"] == "no-store"

def test_chunked_body_rejected_before_buffering_after_rate_limit(app_settings):
    from dataclasses import replace
    from fastapi.testclient import TestClient
    from networkpulse.api import create_app

    opts = replace(app_settings, max_body_bytes=1024, mutation_rate_per_minute=1)
    with TestClient(create_app(opts)) as client:
        headers = {"X-API-Key": opts.api_key, "Content-Type": "application/json"}
        first = client.post("/api/v1/ingest", json={"events": []}, headers=headers)
        assert first.status_code == 422

        def large_chunks():
            yield b"{" + b"x" * 2000 + b"}"

        denied = client.post(
            "/api/v1/ingest", content=large_chunks(),
            headers={**headers, "Transfer-Encoding": "chunked"}
        )
        assert denied.status_code == 429
        assert denied.headers["x-frame-options"] == "DENY"
        assert denied.headers["retry-after"] == "60"

    with TestClient(create_app(opts)) as fresh_client:
        too_big = fresh_client.post(
            "/api/v1/ingest", content=large_chunks(),
            headers={**headers, "Transfer-Encoding": "chunked"}
        )
        assert too_big.status_code == 413
        assert too_big.headers["x-content-type-options"] == "nosniff"
