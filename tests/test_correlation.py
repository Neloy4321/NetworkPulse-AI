from networkpulse.intelligence import correlate_windows
from networkpulse.service import ingest
from networkpulse.storage import build_sessions


def test_flow_correlation_is_bounded_and_explainable(app_settings, trained_detector, samples):
    maker = build_sessions(app_settings.database_url)
    with maker() as session:
        ingest(session, trained_detector, samples[-75:])
        assert correlate_windows(session, min_destinations=2, min_ports=2)
        assert correlate_windows(session, min_destinations=200, min_ports=200) == []
    maker.kw['bind'].dispose()
