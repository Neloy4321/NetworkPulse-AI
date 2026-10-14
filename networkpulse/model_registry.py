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
import math
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
                 max_alert_fraction: float = 1.0,
                 max_fpr_upper_95: float | None = None,
                 release_directory: Path | None = None) -> dict:
        if not name or len(name) > 80 or not all(c.isascii() and (c.isalnum() or c in '-_') for c in name):
            raise ValueError('candidate name must be 1-80 alphanumeric/hyphen/underscore characters')
        if not 0 <= min_f1 <= 1 or not 0 < max_alert_fraction <= 1:
            raise ValueError('invalid validation gates')
        if max_fpr_upper_95 is not None and not 0 < max_fpr_upper_95 <= 1:
            raise ValueError('invalid held-out FPR upper confidence gate')
        release_lineage = None
        if release_directory is not None:
            # SHA-check the candidate release BEFORE unpickling the trusted
            # operator-provided artifact. A checksum alone is not authenticity.
            from networkpulse.training_release import verify_candidate
            checked = verify_candidate(release_directory)
            if checked["candidate"] != name or sha256(model_path) != checked["sha256"]:
                raise ValueError("registered candidate differs from its release manifest")
            manifest_file = Path(release_directory) / "manifest.json"
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            release_lineage = {
                "manifest_sha256": sha256(manifest_file),
                "raw_source_sha256": manifest["dataset"]["raw_source_sha256"],
                "input_identity_sha256": manifest["dataset"]["event_identity_sha256"],
                "functional_holdout_sha256": manifest["model"]["functional_holdout_sha256"],
                "selection": manifest["dataset"]["selection"],
                "provenance_independently_verified": False,
            }
        metadata = Detector.load(model_path).metadata  # TRUSTED LOCAL FILES ONLY.
        metrics = metadata.get('metrics')
        if not isinstance(metrics, dict):
            raise ValueError('held-out labeled evaluation metrics required for candidate gates')
        f1 = float(metrics.get('f1', -1))
        evaluated = int(metadata.get('holdout_count', 0))
        fraction = metrics.get('alerts', evaluated + 1) / max(evaluated, 1)
        if evaluated < 50 or f1 < min_f1 or fraction > max_alert_fraction:
            raise ValueError('model failed explicit candidate F1, holdout or alert-budget gate')
        if max_fpr_upper_95 is not None:
            upper = metrics.get('fpr_wilson_upper_95_one_sided')
            benign_count = int(metrics.get('benign_count', 0))
            if (upper is None or not math.isfinite(float(upper)) or
                    benign_count < 100 or float(upper) > max_fpr_upper_95):
                raise ValueError('model failed held-out benign FPR uncertainty gate')
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
                'gate': {'min_f1': min_f1, 'max_alert_fraction': max_alert_fraction,
                         'max_fpr_upper_95': max_fpr_upper_95},
                'synthetic_only': 'synthetic' in str(metadata.get('source', '')).lower(),
                'release_lineage': release_lineage,
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

    def _verify_production_receipt(self, name: str, evidence_path: Path | None,
                                   *, max_fpr_upper_95: float) -> dict:
        """Conservative, declared-claim gate; evidence authenticity is NOT assured.

        Caller must separately verify the receipt issuer and original source data.
        No test capture labels, SHA checksum or approval text can self-authenticate.
        """
        if evidence_path is None:
            raise ValueError('production requires an independently audited validation receipt')
        if not 0 < max_fpr_upper_95 <= 1:
            raise ValueError('invalid production false-positive budget')
        record = self._read()['candidates'][name]
        if record.get('synthetic_only'):
            raise ValueError('synthetic candidate cannot be promoted for production')
        try:
            receipt = json.loads(Path(evidence_path).read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError('invalid production validation receipt') from exc
        if not isinstance(receipt, dict):
            raise ValueError('production receipt must be an object')
        if receipt.get('candidate_sha256') != record['sha256']:
            raise ValueError('production receipt candidate checksum does not match')
        if not all(receipt.get(key) is True for key in (
                'independent_site_verified', 'live_sensor_contract_verified',
                'training_test_leakage_audited')):
            raise ValueError('production requires site, live-sensor and leakage evidence')
        if not isinstance(receipt.get('approved_by'), str) or not receipt['approved_by'].strip():
            raise ValueError('production requires a named human approver')
        benchmark = receipt.get('evaluation')
        if not isinstance(benchmark, dict):
            raise ValueError('production receipt needs independent evaluation')
        try:
            benign = int(benchmark['benign_count'])
            attack = int(benchmark['attack_count'])
            false_positive = int(benchmark['false_positives'])
            from networkpulse.reliability import wilson_upper_bound
            upper = wilson_upper_bound(false_positive, benign)
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise ValueError('production evaluation has invalid labeled counts') from exc
        if (benign < 200 or attack < 30 or
                upper > max_fpr_upper_95):
            raise ValueError('production holdout too small or benign FPR budget exceeded')
        return {'candidate_sha256': record['sha256'],
                'independent_benign_count': benign, 'independent_attack_count': attack,
                'independent_fpr_upper_95': upper, 'approved_by': receipt['approved_by'].strip(),
                'evidence_sha256': sha256(Path(evidence_path)),
                'authenticity_not_cryptographically_verified': True}

    def promote(self, name: str, destination: Path, *, production: bool = False,
                evidence_path: Path | None = None,
                max_fpr_upper_95: float = .05) -> dict:
        source = self._valid_artifact(name)
        data = self._read()
        proof = None
        if production:
            proof = self._verify_production_receipt(
                name, evidence_path, max_fpr_upper_95=max_fpr_upper_95
            )
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
                                'at': datetime.now(timezone.utc).isoformat(),
                                'production_policy': production,
                                'validation_receipt': proof})
        _write_json(self.catalog, data)
        return {'active': name, 'previous': prior, 'restart_required': True,
                'production_policy': production,
                'warning': 'Production receipt declarations require out-of-band issuer verification'
                           if production else 'Local/demo promotion; not production certified'}

    def rollback(self, destination: Path, *, production: bool = False,
                 evidence_path: Path | None = None) -> dict:
        data = self._read()
        if not data['history'] or data['history'][-1]['from'] is None:
            raise ValueError('no previous registered release available for rollback')
        return self.promote(data['history'][-1]['from'], destination,
                            production=production, evidence_path=evidence_path)

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
                'disagreements': different,
                'disagreement_fraction': round(different / max(1, len(events)), 6),
                'active_alert_fraction': round(sum(x.anomalous for x in before) / max(1, len(events)), 6),
                'candidate_alert_fraction': round(sum(x.anomalous for x in after) / max(1, len(events)), 6),
                'candidate': candidate,
                'warning': 'Shadow comparison only; no model auto-promotion or real-data validation.'}
