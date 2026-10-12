from dataclasses import replace

from fastapi.testclient import TestClient

from networkpulse.api import create_app


def _headers(settings):
    return {'X-API-Key': settings.api_key}


def test_soc_assignment_notes_actor_export_and_detail(client, app_settings, samples):
    flows = {'events': [f.model_dump(mode='json') for f in samples[-70:]]}
    r = client.post('/api/v1/ingest', json=flows, headers=_headers(app_settings))
    assert r.status_code == 200
    alerts = client.get('/api/v1/alerts').json()
    assert alerts
    alert_id = alerts[0]['id']
    assert client.get(f'/api/v1/alerts/{alert_id}/detail').status_code == 200
    assert client.post(f'/api/v1/alerts/{alert_id}/notes', json={'note': 'trace checked'}).status_code == 401
    assert client.post(f'/api/v1/alerts/{alert_id}/notes',
                       json={'note': 'trace checked'}, headers=_headers(app_settings)).status_code == 200
    assigned = client.patch(f'/api/v1/alerts/{alert_id}/assignment',
                            json={'assigned_to': 'analyst-one', 'note': 'review started'},
                            headers=_headers(app_settings))
    assert assigned.status_code == 200, assigned.text
    triage = client.patch(f'/api/v1/alerts/{alert_id}',
                          json={'status': 'investigating', 'note': 'analyzing'},
                          headers=_headers(app_settings))
    assert triage.status_code == 200
    detail = client.get(f'/api/v1/alerts/{alert_id}/detail').json()
    assert detail['assigned_to'] == 'analyst-one'
    assert len(detail['notes']) == 2
    assert detail['event']['src_ip']
    history = client.get(f'/api/v1/alerts/{alert_id}/history').json()
    assert history[0]['actor'] == 'local-operator'
    export = client.get('/api/v1/alerts/export.csv')
    assert export.status_code == 200 and 'analyst-one' in export.text
    assert 'alert_id' in export.text


def test_security_limits_and_chunked_upload(app_settings):
    settings = replace(app_settings, mutation_rate_per_minute=2,
                       max_body_bytes=1024)
    with TestClient(create_app(settings)) as client:
        too_big = client.post('/api/v1/ingest', content=b'x' * 2000,
                              headers={**_headers(settings), 'Content-Type': 'application/json'})
        assert too_big.status_code == 413
        assert client.get('/health/live').headers['x-content-type-options'] == 'nosniff'
        a = client.post('/api/v1/ingest', json={'events': []}, headers=_headers(settings))
        b = client.post('/api/v1/ingest', json={'events': []}, headers=_headers(settings))
        c = client.post('/api/v1/ingest', json={'events': []}, headers=_headers(settings))
        # Oversize request has no token charge; Pydantic rejects invalid zero-length batch.
        assert a.status_code == b.status_code == 422
        assert c.status_code == 429
        assert c.headers['retry-after'] == '60'
