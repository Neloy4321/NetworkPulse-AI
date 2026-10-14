"""Security adversarial tests: PKCE state, session revocation and cookie CSRF."""
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from networkpulse.api import create_app
from networkpulse.security.browser_login import BrowserLogin, SESSION_COOKIE
from networkpulse.security.oidc import Principal


class MemoryRedis:
    def __init__(self):
        self.items = {}

    def ping(self):
        return True

    def set(self, key, value, ex=None, nx=False):
        if nx and key in self.items:
            return False
        self.items[key] = value
        return True

    def get(self, key):
        return self.items.get(key)

    def getdel(self, key):
        return self.items.pop(key, None)

    def delete(self, key):
        self.items.pop(key, None)

    def eval(self, *args):
        return 1

    def close(self):
        pass


def test_state_is_bound_to_cookie_and_single_use():
    store = MemoryRedis()
    auth = BrowserLogin(
        store, "https://idp.example/realm",
        "https://idp.example/auth", "https://idp.example/token",
        "public-client", "https://soc.example",
    )
    url, state = auth.start()
    query = parse_qs(urlsplit(url).query)
    assert query["code_challenge_method"] == ["S256"]
    assert query["nonce"]
    assert query["state"] == [state]
    with pytest.raises(HTTPException):
        auth.consume(state, "forged")
    entry = auth.consume(state, state)
    assert len(entry["verifier"]) > 40
    with pytest.raises(HTTPException):
        auth.consume(state, state)
    with pytest.raises(ValueError):
        BrowserLogin(
            store, "https://idp.example",
            "https://attacker.example/auth", "https://idp.example/token",
            "client", "https://soc.example",
        )


def test_oidc_login_csrf_rbac_and_logout(monkeypatch, app_settings, samples):
    store = MemoryRedis()
    monkeypatch.setattr("redis.Redis.from_url", lambda *a, **k: store)

    class FakeVerifier:
        def __init__(self, *a, **k):
            pass

        def verify(self, token):
            if token in {"viewer", "analyst", "admin"}:
                return Principal("oidc-test-user", token)
            raise HTTPException(401, detail="Invalid access token")

    async def exchange(self, code, pending, verifier):
        assert code == "valid-code-1234"
        assert pending["verifier"]
        return "analyst", 120

    monkeypatch.setattr("networkpulse.api.TokenVerifier", FakeVerifier)
    monkeypatch.setattr(BrowserLogin, "exchange", exchange)
    opts = replace(
        app_settings, auth_mode="oidc",
        oidc_issuer="https://idp.example", oidc_audience="api",
        oidc_jwks_url="https://idp.example/keys",
        security_redis_url="redis://fake/0", browser_oidc_enabled=True,
        oidc_auth_url="https://idp.example/auth",
        oidc_token_url="https://idp.example/token",
        oidc_client_id="public-client", public_origin="https://soc.example",
    )
    with TestClient(create_app(opts), base_url="https://soc.example") as client:
        assert client.get("/api/v1/summary").status_code == 401
        begin = client.get("/auth/login", follow_redirects=False)
        assert begin.status_code == 302
        assert "secure" in begin.headers["set-cookie"].lower()
        assert "httponly" in begin.headers["set-cookie"].lower()
        state = parse_qs(urlsplit(begin.headers["location"]).query)["state"][0]
        result = client.get(
            "/auth/callback", params={"state": state, "code": "valid-code-1234"},
            follow_redirects=False,
        )
        assert result.status_code == 303
        assert SESSION_COOKIE in result.headers["set-cookie"]
        assert client.get("/api/v1/summary").status_code == 200
        info = client.get("/auth/session")
        assert info.status_code == 200
        assert info.json()["role"] == "analyst"
        payload = {"events": [e.model_dump(mode="json") for e in samples[-10:]]}
        assert client.post("/api/v1/ingest", json=payload).status_code == 403
        csrf = info.json()["csrf_token"]
        assert client.post(
            "/api/v1/ingest", json=payload,
            headers={"X-CSRF-Token": csrf, "Origin": "https://attacker.example"},
        ).status_code == 403
        passed = client.post(
            "/api/v1/ingest", json=payload,
            headers={"X-CSRF-Token": csrf, "Origin": "https://soc.example"},
        )
        assert passed.status_code == 200
        assert client.post("/auth/logout").status_code == 403
        logout = client.post("/auth/logout", headers={
            "Origin": "https://soc.example", "X-CSRF-Token": csrf,
        })
        assert logout.status_code == 204
        assert client.get("/auth/session").status_code == 401
        assert client.get("/api/v1/summary").status_code == 401
        replay = client.get(
            "/auth/callback", params={"state": state, "code": "valid-code-1234"},
            follow_redirects=False,
        )
        assert replay.status_code == 401


def test_real_rs256_oidc_identity_nonce_and_pkce_exchange(monkeypatch):
    import asyncio
    import time
    import httpx
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    from networkpulse.security.oidc import TokenVerifier

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key()
    now = int(time.time())
    access = jwt.encode({
        "iss": "https://idp.example", "aud": "networkpulse-api",
        "sub": "alice", "exp": now + 600, "iat": now,
        "networkpulse_role": "analyst",
    }, key, algorithm="RS256")
    nonce = "nonce-protected"
    identity_claims = {
        "iss": "https://idp.example", "aud": "public-client", "sub": "alice",
        "exp": now + 600, "iat": now, "nonce": nonce,
    }
    response_id_token = jwt.encode(identity_claims, key, algorithm="RS256")
    original_client = httpx.AsyncClient

    def transport(request):
        assert str(request.url) == "https://idp.example/token"
        assert b"code_verifier" in request.content
        return httpx.Response(200, json={
            "access_token": access, "id_token": response_id_token,
            "token_type": "Bearer",
        })

    monkeypatch.setattr(
        "networkpulse.security.browser_login.httpx.AsyncClient",
        lambda **options: original_client(transport=httpx.MockTransport(transport), **options),
    )
    verifier = TokenVerifier(
        "https://idp.example", "networkpulse-api", "https://idp.example/keys"
    )
    verifier.jwks.get_signing_key_from_jwt = lambda token: type("Key", (), {"key": public})()
    browser = BrowserLogin(
        MemoryRedis(), "https://idp.example", "https://idp.example/auth",
        "https://idp.example/token", "public-client", "https://soc.example"
    )
    received, ttl = asyncio.run(browser.exchange(
        "verified-auth-code", {"verifier": "generated-verifier", "nonce": nonce},
        verifier,
    ))
    assert received == access
    assert 500 <= ttl <= 900
    with pytest.raises(HTTPException) as error:
        asyncio.run(browser.exchange(
            "verified-auth-code", {"verifier": "generated-verifier", "nonce": "incorrect"},
            verifier,
        ))
    assert error.value.status_code == 401

    # Multi-audience OIDC ID tokens require azp bound to this client.
    identity_claims["aud"] = ["public-client", "other-client"]
    response_id_token = jwt.encode(identity_claims, key, algorithm="RS256")
    with pytest.raises(HTTPException) as error:
        asyncio.run(browser.exchange(
            "verified-auth-code", {"verifier": "generated-verifier", "nonce": nonce},
            verifier,
        ))
    assert error.value.status_code == 401

    identity_claims["azp"] = "other-client"
    response_id_token = jwt.encode(identity_claims, key, algorithm="RS256")
    with pytest.raises(HTTPException):
        asyncio.run(browser.exchange(
            "verified-auth-code", {"verifier": "generated-verifier", "nonce": nonce},
            verifier,
        ))

    identity_claims["azp"] = "public-client"
    response_id_token = jwt.encode(identity_claims, key, algorithm="RS256")
    verified, ttl = asyncio.run(browser.exchange(
        "verified-auth-code", {"verifier": "generated-verifier", "nonce": nonce},
        verifier,
    ))
    assert verified == access and ttl > 0
