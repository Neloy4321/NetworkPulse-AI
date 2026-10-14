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
import fcntl
from contextlib import contextmanager
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
        self.journal = self.root / '.pending-model-release.json'
        self.rollback_copy = self.root / '.pending-previous-model.joblib'

    @contextmanager
    def _exclusive(self, *, allow_recovery: bool = False):
        # Linux POSIX flock: serializes independent CLI operator processes.
        # Single-node shared filesystem only; NFS/distributed locks not assumed.
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.root / '.model-release.lock',
                     os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            if self.journal.exists() and not allow_recovery:
                raise RuntimeError(
                    'Unresolved model release journal: inspect/repair deployed '
                    'artifact and catalog before further mutations'
                )
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _read(self) -> dict:
        if not self.catalog.exists():
            return {'candidates': {}, 'active': None, 'history': []}
        return json.loads(self.catalog.read_text(encoding='utf-8'))

    def register(self, name: str, model_path: Path, *, min_f1: float = 0.0,
                 max_alert_fraction: float = 1.0,
                 max_fpr_upper_95: float | None = None,
                 release_directory: Path | None = None) -> dict:
        with self._exclusive():
            return self._register_locked(
                name, model_path, min_f1=min_f1,
                max_alert_fraction=max_alert_fraction,
                max_fpr_upper_95=max_fpr_upper_95,
                release_directory=release_directory,
            )

    def _register_locked(self, name: str, model_path: Path, *, min_f1: float = 0.0,
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
                                   *, max_fpr_upper_95: float,
                                   trust_store: Path | None = None,
                                   previous_active: str | None = None,
                                   operation: str = 'promote') -> dict:
        """Signature verified against pre-provisioned Ed25519 trusted key."""

        if evidence_path is None:
            raise ValueError('production requires an independently audited validation receipt')
        record = self._read()['candidates'][name]
        if record.get('synthetic_only'):
            raise ValueError('synthetic candidate cannot be promoted for production')
        if trust_store is None:
            raise ValueError('production requires an out-of-band trusted Ed25519 public key store')
        from networkpulse.release_approval import verify_signed_approval
        signed = verify_signed_approval(evidence_path, trust_store)
        if not 0 < max_fpr_upper_95 <= 1:
            raise ValueError('invalid production false-positive budget')
        receipt = signed['payload']
        if receipt['previous_active'] != previous_active:
            raise ValueError('Signed approval is bound to a different previous active model')
        if receipt['operation'] != operation:
            raise ValueError('Signed approval operation does not match requested release action')
        if any(h.get('validation_receipt', {}).get('change_id') == receipt['change_id']
               for h in self._read()['history'] if isinstance(h.get('validation_receipt'), dict)):
            raise ValueError('Production change ID was already consumed; replay refused')
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
                'signer_key_id': signed['signer_key_id'],
                'change_id': receipt['change_id'],
                'signature_verified': True,
                'receipt_expires_utc': signed['receipt_expires_utc'],
                'issuer_trust_requires_external_provisioning': True}

    def promote(self, name: str, destination: Path, *, production: bool = False,
                evidence_path: Path | None = None,
                max_fpr_upper_95: float = .05,
                trust_store: Path | None = None) -> dict:
        with self._exclusive():
            return self._promote_locked(
                name, destination, production=production,
                evidence_path=evidence_path, max_fpr_upper_95=max_fpr_upper_95,
                trust_store=trust_store,
            )

    def _promote_locked(self, name: str, destination: Path, *,
                        production: bool, evidence_path: Path | None,
                        max_fpr_upper_95: float, trust_store: Path | None,
                        rollback_action: bool = False) -> dict:
        source = self._valid_artifact(name)
        data = self._read()
        proof = None
        prior = data.get('active')
        if production:
            proof = self._verify_production_receipt(
                name, evidence_path, max_fpr_upper_95=max_fpr_upper_95,
                trust_store=trust_store, previous_active=prior,
                operation='rollback' if rollback_action else 'promote',
            )
        destination = Path(destination)
        if prior is not None:
            if prior not in data['candidates'] or not destination.is_file():
                raise ValueError('active deployed model is missing from registry/destination')
            if sha256(destination) != data['candidates'][prior]['sha256']:
                raise ValueError('active deployed model checksum mismatch; release refused')
        elif destination.exists():
            raise ValueError('existing deployed file is not registered as active; release refused')

        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(prefix='.model-', dir=destination.parent)
        os.close(fd)
        journal_written = False
        swapped = False
        try:
            shutil.copyfile(source, temp)
            if sha256(Path(temp)) != data['candidates'][name]['sha256']:
                raise ValueError('model changed during promotion')
            if prior is not None:
                shutil.copyfile(destination, self.rollback_copy)
                os.chmod(self.rollback_copy, 0o600)
                if sha256(self.rollback_copy) != data['candidates'][prior]['sha256']:
                    raise ValueError('previous model backup checksum mismatch')
            _write_json(self.journal, {
                'previous': prior, 'target': name,
                'destination': str(destination.resolve()),
                'target_sha256': data['candidates'][name]['sha256'],
                'previous_sha256': data['candidates'][prior]['sha256'] if prior else None,
                'action': 'rollback' if rollback_action else 'promote',
                'instruction': 'Quarantine; do not deploy until registry and file agree.',
            })
            journal_written = True
            os.replace(temp, destination)
            swapped = True
            data['active'] = name
            data['history'].append({
                'from': prior, 'to': name,
                'at': datetime.now(timezone.utc).isoformat(),
                'action': 'rollback' if rollback_action else 'promote',
                'production_policy': production,
                'validation_receipt': proof,
            })
            _write_json(self.catalog, data)
        except Exception:
            if swapped:
                try:
                    if prior is None:
                        destination.unlink(missing_ok=True)
                    else:
                        if sha256(self.rollback_copy) != data['candidates'][prior]['sha256']:
                            raise RuntimeError('previous model restore checksum mismatch')
                        os.replace(self.rollback_copy, destination)
                except Exception:
                    # Preserve on-disk journal and backup for manual recovery.
                    raise RuntimeError('Release restore failed: manual journal recovery required')
            if journal_written:
                self.journal.unlink(missing_ok=True)
            raise
        finally:
            Path(temp).unlink(missing_ok=True)
        self.rollback_copy.unlink(missing_ok=True)
        self.journal.unlink(missing_ok=True)
        return {
            'active': name, 'previous': prior, 'restart_required': True,
            'production_policy': production,
            'warning': 'Signed receipt verifies trusted key, not factual evaluation or site independence'
                       if production else 'Local/demo promotion; not production certified',
        }

    def rollback(self, destination: Path, *, production: bool = False,
                 evidence_path: Path | None = None,
                 trust_store: Path | None = None) -> dict:
        with self._exclusive():
            data = self._read()
            if (not data['history'] or data['history'][-1]['from'] is None or
                    data['history'][-1].get('action') == 'rollback'):
                raise ValueError('no previous registered release available for rollback')
            return self._promote_locked(
                data['history'][-1]['from'], destination, production=production,
                evidence_path=evidence_path, trust_store=trust_store,
                max_fpr_upper_95=.05, rollback_action=True,
            )

    def verify_active(self, destination: Path) -> dict:
        """Read-only startup/operator invariant. Never loads joblib/pickle."""
        if self.journal.exists():
            raise RuntimeError('unresolved release journal; active model untrusted')
        data = self._read()
        active = data.get('active')
        if active is None:
            raise ValueError('no registered active release')
        record = data['candidates'].get(active)
        if not record:
            raise ValueError('active candidate missing from registry')
        path = Path(destination)
        if not path.is_file() or sha256(path) != record['sha256']:
            raise ValueError('deployed model artifact checksum differs from registered release')
        # A stale or modified candidate cannot be treated as a verified release.
        # The deployed file alone is not sufficient to establish registry integrity.
        self._valid_artifact(active)
        return {
            'active': active, 'sha256': record['sha256'],
            'feature_version': record.get('feature_version'),
            'synthetic_only': record.get('synthetic_only', False),
            'consistent': True,
            'history_entries': len(data['history']),
            'warning': 'Checksum consistency is not code provenance or site performance approval',
        }

    def recover_interrupted(self, destination: Path, *,
                            expected_target_sha256: str,
                            confirm: bool = False) -> dict:
        """Reconcile an interrupted single-node rollout from its journal.

        A release whose catalog commit succeeded is retained; otherwise the
        saved previous artifact is atomically restored. No unknown bytes are
        installed and all mismatches retain journal evidence for investigation.
        """
        if not confirm:
            raise ValueError('Explicit interrupted-release recovery approval required')
        with self._exclusive(allow_recovery=True):
            if not self.journal.exists():
                raise ValueError('no interrupted release journal exists')
            journal = json.loads(self.journal.read_text(encoding='utf-8'))
            destination = Path(destination).resolve()
            if (journal.get('destination') != str(destination) or
                    journal.get('target_sha256') != expected_target_sha256):
                raise ValueError('journal target/destination differs from operator approval')
            prior, target = journal['previous'], journal['target']
            expected_prior = journal['previous_sha256']
            catalog = self._read()
            active = catalog.get('active')
            current = sha256(destination) if destination.is_file() else None
            if active == target and current == expected_target_sha256:
                result = 'committed_release_verified'
            elif active == prior:
                if prior is None:
                    if current not in (None, expected_target_sha256):
                        raise ValueError('unknown deployed bytes; manual recovery required')
                    destination.unlink(missing_ok=True)
                elif current == expected_prior:
                    pass
                elif current == expected_target_sha256:
                    if (not self.rollback_copy.is_file() or
                            sha256(self.rollback_copy) != expected_prior):
                        raise ValueError('previous artifact backup missing/mismatched')
                    os.replace(self.rollback_copy, destination)
                else:
                    raise ValueError('unrecognized deployed artifact; manual recovery required')
                result = 'previous_release_restored'
            else:
                raise ValueError('catalog state differs from interrupted release journal')
            self.rollback_copy.unlink(missing_ok=True)
            self.journal.unlink(missing_ok=True)
            return {'result': result, 'active': active,
                    'consistent': True, 'manual_restart_required': True}

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
