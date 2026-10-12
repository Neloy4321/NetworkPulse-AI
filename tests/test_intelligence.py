from networkpulse.intelligence import host_behavior
from networkpulse.service import ingest
from networkpulse.storage import build_sessions
from networkpulse.detector import Detector


def test_source_aggregation(client,app_settings,samples):
    model=Detector.load(app_settings.model_path)
    maker=build_sessions(app_settings.database_url)
    with maker() as session:
        ingest(session,model,samples[-80:])
        result=host_behavior(session,scan_ports=2)
    assert result["flow_count"]==80
    assert sum(h["flows"] for h in result["hosts"]) <= 80
    assert result["hosts"]
    api=client.get("/api/v1/intelligence/hosts")
    assert api.status_code==200
    assert "hosts" in api.json()
    assert client.get("/api/v1/intelligence/hosts?limit_hosts=9999").status_code==422
