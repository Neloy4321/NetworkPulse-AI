
def auth(settings):
    return {"X-API-Key": settings.api_key}


def test_readiness_and_dashboard(client):
    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").status_code == 200
    assert client.get("/").status_code == 200
    assert "NETWORKPULSE" in client.get("/").text
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/not-existent.js").status_code == 404


def test_authentication_ingest_and_idempotency(client, app_settings, samples):
    batch = {"events": [x.model_dump(mode="json") for x in samples[-30:]]}
    assert client.post("/api/v1/ingest", json=batch).status_code == 401
    assert client.post("/api/v1/ingest", json=batch, headers={"X-API-Key": "invalid"}).status_code == 401
    r = client.post("/api/v1/ingest", json=batch, headers=auth(app_settings))
    assert r.status_code == 200, r.text
    assert r.json()["inserted"] == 30
    replay = client.post("/api/v1/ingest", json=batch, headers=auth(app_settings))
    assert replay.json()["inserted"] == 0
    assert replay.json()["duplicates"] == 30
    summary = client.get("/api/v1/summary").json()
    assert summary["flows"] == 30
    assert sum(summary["protocols"].values()) == 30


def test_alert_lifecycle_and_audit(client, app_settings, samples):
    events = [x.model_dump(mode="json") for x in samples[-70:]]
    r = client.post("/api/v1/ingest", json={"events": events}, headers=auth(app_settings))
    assert r.status_code == 200
    assert r.json()["alerts_created"] > 0
    items = client.get("/api/v1/alerts").json()
    assert items
    alert = items[0]
    path = f"/api/v1/alerts/{alert['id']}"
    assert client.patch(path, json={"status": "investigating", "note": "Checking source"}).status_code == 401
    updated = client.patch(path, json={"status": "investigating", "note": "Investigating source activity"}, headers=auth(app_settings))
    assert updated.status_code == 200
    assert updated.json()["status"] == "investigating"
    history = client.get(path + "/history").json()
    assert len(history) == 1 and history[0]["old_status"] == "open"
    assert history[0]["new_status"] == "investigating"
    assert len(client.get("/api/v1/alerts?status=investigating").json()) == 1
    assert client.patch("/api/v1/alerts/9999", json={"status": "open", "note": "valid note"}, headers=auth(app_settings)).status_code == 404


def test_request_validation_and_trends(client, app_settings, samples):
    assert client.post("/api/v1/ingest", json={"events": []}, headers=auth(app_settings)).status_code == 422
    assert client.get("/api/v1/events?limit=101").status_code == 422
    assert client.get("/api/v1/alerts?status=oops").status_code == 422
    assert client.get("/api/v1/trends").json() == []
    batch = [x.model_dump(mode="json") for x in samples[-20:]]
    client.post("/api/v1/ingest", json={"events": batch}, headers=auth(app_settings))
    assert len(client.get("/api/v1/events?limit=5").json()) == 5
    assert client.get("/api/v1/trends").json()


def test_reject_malformed_flow(client, app_settings, samples):
    event = samples[-1].model_dump(mode="json")
    event["src_ip"] = "127.0.0.1; rm -rf /"
    assert client.post("/api/v1/ingest", json={"events": [event]}, headers=auth(app_settings)).status_code == 422
