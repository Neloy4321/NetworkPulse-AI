"""Local model release registry with explicit gates, integrity and rollback.

This is a single-node artifact registry. It never downloads or loads untrusted models.
Production promotion requires additional independent dataset validation and operators.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from networkpulse.detector import Detector


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.registry-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class ModelRegistry:
    """Operator-controlled model lifecycle with checksum validation."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.catalog = self.root / 'registry.json'

    def _read(self) -> dict:
        if not self.catalog.exists():
            return {'candidates': {}, 'active': None, 'history': []}
        return json.loads(self.catalog.read_text(encoding='utf-8'))

    def register(self, name: str, model_path: Path, *, min_f1: float = 0.0,
                 max_alert_fraction: float = 1.0) -> dict:
        if not name or len(name) > 80 or not all(c.isascii() and (c.isalnum() or c in '-_') for c in name):
            raise ValueError('candidate name must be 1-80 alphanumeric/hyphen/underscore characters')
        if not 0 <= min_f1 <= 1 or not 0 < max_alert_fraction <= 1:
            raise ValueError('invalid validation gates')
        metadata = Detector.load(model_path).metadata  # TRUSTED LOCAL FILES ONLY.
        metrics = metadata.get('metrics')
        if not isinstance(metrics, dict):
            raise ValueError('held-out labeled evaluation metrics required for candidate gates')
        f1 = float(metrics.get('f1', -1))
        evaluated = int(metadata.get('holdout_count', 0))
        fraction = metrics.get('alerts', evaluated + 1) / max(evaluated, 1)
        if evaluated < 50 or f1 < min_f1 or fraction > max_alert_fraction:
            raise ValueError('model failed explicit candidate F1, holdout or alert-budget gate')
        registry = self._read()
        if name in registry['candidates']:
            raise ValueError('candidate name already registered; use a new immutable version')
        self.root.mkdir(parents=True, exist_ok=True)
        destination = self.root / f'{name}.joblib'
        if destination.exists():
            raise ValueError('candidate artifact already exists')
        shutil.copyfile(model_path, destination)
        try:
            record = {
                'sha256': sha256(destination), 'source': metadata.get('source'),
                'feature_version': metadata.get('feature_version'), 'metrics': metrics,
                'registered_at': datetime.now(timezone.utc).isoformat(),
                'gate': {'min_f1': min_f1, 'max_alert_fraction': max_alert_fraction},
                'synthetic_only': 'synthetic' in str(metadata.get('source', '')).lower(),
            }
            registry['candidates'][name] = record
            _write_json(self.catalog, registry)
            return record
        except Exception:
            destination.unlink(missing_ok=True)
            raise

    def _valid_artifact(self, name: str) -> Path:
        data = self._read()
        if name not in data['candidates']:
            raise ValueError('unknown candidate')
        path = self.root / f'{name}.joblib'
        if not path.is_file() or sha256(path) != data['candidates'][name]['sha256']:
            raise ValueError('model artifact integrity check failed')
        return path

    def promote(self, name: str, destination: Path) -> dict:
        source = self._valid_artifact(name)
        data = self._read()
        prior = data.get('active')
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(prefix='.model-', dir=destination.parent)
        os.close(fd)
        try:
            shutil.copyfile(source, temp)
            if sha256(Path(temp)) != data['candidates'][name]['sha256']:
                raise ValueError('model changed during promotion')
            os.replace(temp, destination)
        finally:
            Path(temp).unlink(missing_ok=True)
        data['active'] = name
        data['history'].append({'from': prior, 'to': name,
                                'at': datetime.now(timezone.utc).isoformat()})
        _write_json(self.catalog, data)
        return {'active': name, 'previous': prior, 'restart_required': True}

    def rollback(self, destination: Path) -> dict:
        data = self._read()
        if not data['history'] or data['history'][-1]['from'] is None:
            raise ValueError('no previous registered release available for rollback')
        return self.promote(data['history'][-1]['from'], destination)

    def status(self) -> dict:
        data = self._read()
        return {'active': data['active'], 'candidates': data['candidates'],
                'history': data['history']}

    def shadow(self, candidate: str, deployed: Path, events: list) -> dict:
        alternative = Detector.load(self._valid_artifact(candidate))
        current = Detector.load(deployed)
        before = current.score(events)
        after = alternative.score(events)
        different = sum(a.anomalous != b.anomalous for a, b in zip(before, after))
        return {'events': len(events), 'active_alerts': sum(x.anomalous for x in before),
                'candidate_alerts': sum(x.anomalous for x in after),
                'disagreements': different, 'candidate': candidate,
                'warning': 'Shadow comparison only; no model auto-promotion or real-data validation.'}
