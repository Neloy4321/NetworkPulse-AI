"""Additive upgrade from already-shipped v0.2 with data preservation."""
from alembic import command
from sqlalchemy import create_engine, text

from networkpulse.migrations import _config, upgrade_database
from networkpulse.storage import build_sessions


def test_upgrade_v02_to_v04_keeps_event_and_alert(tmp_path):
    url = 'sqlite:///' + str(tmp_path / 'v02.db')
    engine = create_engine(url)
    with engine.begin() as connection:
        command.upgrade(_config(connection), '0002_counter_integrity')
        connection.execute(text("""INSERT INTO network_events
            (id, timestamp, source, src_ip, dst_ip, orig_bytes, resp_bytes, orig_pkts, resp_pkts)
            VALUES ('v02-event', '2026-01-01', 'zeek', '10.0.0.1', '10.0.0.2', 12, 10, 2, 1)"""))
        connection.execute(text("""INSERT INTO alerts (id, event_id, severity, status, reasons)
            VALUES (88, 'v02-event', 'high', 'open', '[]')"""))
    engine.dispose()
    assert upgrade_database(url)['revision'] == '0003_soc_accountability'
    maker = build_sessions(url)
    with maker() as session:
        from networkpulse.storage import Alert, NetworkEvent
        assert session.get(Alert, 88).event_id == 'v02-event'
        assert session.get(NetworkEvent, 'v02-event').orig_bytes == 12
    maker.kw['bind'].dispose()
