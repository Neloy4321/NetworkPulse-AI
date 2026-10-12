"""Conservative archival of old, unalerted flows, with integrity manifest.

Manual operator job; audits and alerted events are intentionally never purged.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from networkpulse.storage import Alert, NetworkEvent


def archive_unalerted(session: Session, *, before: datetime, destination: Path,
                      commit: bool = False, max_rows: int = 5000) -> dict:
    if before.tzinfo is None:
        raise ValueError('UTC-aware archival cutoff required')
    if max_rows < 1 or max_rows > 100000:
        raise ValueError('max_rows must be in 1..100000')
    # Never delete alerted events: historical incident review must retain evidence.
    alerted = select(Alert.event_id)
    query = (select(NetworkEvent).where(NetworkEvent.timestamp < before,
              NetworkEvent.id.not_in(alerted))
              .order_by(NetworkEvent.timestamp, NetworkEvent.id).limit(max_rows))
    rows = session.scalars(query).all()
    result = {'eligible': len(rows), 'cutoff': before.isoformat(), 'committed': False}
    if not commit or not rows:
        return result
    path = Path(destination)
    if path.exists() or path.with_suffix(path.suffix + '.manifest.json').exists():
        raise ValueError('archive destination must be new to prevent overwriting evidence')
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    # One line per flow; deterministic serialization permits integrity checks.
    with path.open('xb') as stream:
        for row in rows:
            data = {column.name: getattr(row, column.name) for column in NetworkEvent.__table__.columns}
            for key, value in data.items():
                if isinstance(value, datetime):
                    data[key] = value.isoformat()
            line = (json.dumps(data, sort_keys=True, separators=(',', ':')) + '\n').encode()
            stream.write(line)
            digest.update(line)
        stream.flush()
        os.fsync(stream.fileno())
    manifest = path.with_suffix(path.suffix + '.manifest.json')
    manifest.write_text(json.dumps({'sha256': digest.hexdigest(), 'rows': len(rows),
                                    'cutoff': before.isoformat(),
                                    'policy': 'unalerted-only; alert history retained'}, indent=2) + '\n')
    ids = [row.id for row in rows]
    session.rollback()  # End the read transaction before atomic deletion.
    # Deletion is transactional. If this fails, archive evidence remains (safe to retry
    # with a new filename); successful deletes can never orphan AlertAudit rows.
    with session.begin():
        deleted = session.execute(delete(NetworkEvent).where(NetworkEvent.id.in_(ids),
                                  NetworkEvent.id.not_in(alerted),
                                  NetworkEvent.timestamp < before)).rowcount
    result.update({'committed': True, 'deleted': deleted,
                   'path': str(path), 'sha256': digest.hexdigest()})
    return result


def cutoff_days(days: int) -> datetime:
    if days < 1:
        raise ValueError('retention must be at least one day')
    return datetime.now(timezone.utc) - timedelta(days=days)
