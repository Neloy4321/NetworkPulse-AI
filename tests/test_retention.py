import hashlib
import json
from datetime import timedelta

from sqlalchemy import func, select

from networkpulse.detector import train
from networkpulse.retention import archive_unalerted
from networkpulse.service import ingest
from networkpulse.simulator import sample_flows
from networkpulse.storage import Alert, NetworkEvent, build_sessions


def test_archival_never_deletes_alerted_flows(app_settings, tmp_path):
    maker = build_sessions(app_settings.database_url)
    flows = sample_flows(180, seed=12)
    detector = train(flows, seed=12)
    with maker() as session:
        res = ingest(session, detector, flows[-45:])
        assert res['alerts_created'] > 0
        before = flows[-1].timestamp + timedelta(days=1)
        file = tmp_path / 'archive.jsonl'
        dry = archive_unalerted(session, before=before, destination=file)
        assert not file.exists()
        assert not dry['committed']
        all_count = session.scalar(select(func.count(NetworkEvent.id)))
        alerts = session.scalar(select(func.count(Alert.id)))
        real = archive_unalerted(session, before=before, destination=file, commit=True)
        assert real['deleted'] == all_count - alerts
        assert real['deleted'] == dry['eligible']
        manifest = json.loads((tmp_path / 'archive.jsonl.manifest.json').read_text())
        assert manifest['rows'] == real['deleted']
        assert manifest['sha256'] == hashlib.sha256(file.read_bytes()).hexdigest()
        assert session.scalar(select(func.count(NetworkEvent.id))) == alerts
        assert session.scalar(select(func.count(Alert.id))) == alerts
    maker.kw['bind'].dispose()
