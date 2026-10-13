from networkpulse.detector import Detector
from networkpulse.service import ingest
from networkpulse.storage import build_sessions


def test_filter_sort_and_pagination(client,app_settings,samples):
    maker=build_sessions(app_settings.database_url)
    with maker() as session:
        ingest(session,Detector.load(app_settings.model_path),samples[-100:])
    all_alerts=client.get('/api/v1/alerts?limit=100').json()
    assert all_alerts
    selected=all_alerts[0]
    filtered=client.get('/api/v1/alerts',params={'src_ip':selected['src_ip']}).json()
    assert filtered
    assert all(a['src_ip']==selected['src_ip'] for a in filtered)
    second=client.get('/api/v1/alerts',params={'limit':2,'offset':2}).json()
    assert second==all_alerts[2:4]
    high=client.get('/api/v1/alerts',params={'min_risk':75}).json()
    assert all(x['risk']>=75 for x in high)
    for invalid in ['?order=shuffled','?min_risk=101','?severity=unknown','?offset=-1']:
        assert client.get('/api/v1/alerts'+invalid).status_code==422



def test_default_dashboard_omits_empty_optional_filters(client):
    """Regression: blank dropdown values must not become invalid API query values."""
    from pathlib import Path

    script = Path("networkpulse/static/app.js").read_text(encoding="utf-8")
    assert "if (value) alertParams.set(name, value);" in script
    assert "getJson('/api/v1/alerts?' + alertParams.toString())" in script
    assert client.get("/api/v1/alerts?limit=25&offset=0&order=newest").status_code == 200
    assert client.get("/api/v1/alerts?status=&severity=").status_code == 422
