"""RBAC negative and positive integration tests for the FastAPI scopes."""

from dataclasses import replace

from fastapi import HTTPException
from fastapi.testclient import TestClient

from networkpulse.api import create_app
from networkpulse.security.oidc import Principal


class FakeVerifier:
    def __init__(self,*args,**kwargs):
        pass
    def verify(self,token):
        if token=="viewer":
            return Principal("u1","viewer")
        if token=="analyst":
            return Principal("u2","analyst")
        if token=="admin":
            return Principal("u3","admin")
        raise HTTPException(401,detail="Invalid token")


def test_oidc_protected_reads_and_roles(monkeypatch,app_settings,samples):
    monkeypatch.setattr("networkpulse.api.TokenVerifier",FakeVerifier)
    settings=replace(app_settings,auth_mode="oidc",oidc_issuer="https://auth.test",
                     oidc_jwks_url="https://auth.test/jwks",oidc_audience="api")
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/v1/alerts").status_code==401
        assert client.get("/").status_code==401
        assert client.get("/api/v1/summary",headers={"Authorization":"Bearer viewer"}).status_code==200
        assert client.get("/metrics",headers={"Authorization":"Bearer viewer"}).status_code==403
        assert client.get("/metrics",headers={"Authorization":"Bearer admin"}).status_code==200
        batch={"events":[x.model_dump(mode="json") for x in samples[-25:]]}
        assert client.post("/api/v1/ingest",json=batch,headers={"Authorization":"Bearer viewer"}).status_code==403
        assert client.post("/api/v1/ingest",json=batch,headers={"Authorization":"Bearer analyst"}).status_code==200
        assert client.get("/api/v1/alerts",headers={"Authorization":"Bearer bad"}).status_code==401
        assert client.get("/health/live").status_code==200
