"""Offline CIC-IDS2017 CICFlowMeter CSV benchmark with train/test provenance.

This is a *separate evaluation adapter*, not a Zeek/Suricata event conversion.
Prepared CSV exports have variable column spellings and may lack trustworthy
identity/timestamps. Never fabricate these missing fields.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import random
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction import DictVectorizer
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import RobustScaler

from networkpulse.evaluation.unsw import metrics

CORE = {
    'duration': ('Flow Duration',),
    'fwd_packets': ('Total Fwd Packets', 'Total Forward Packets'),
    'bwd_packets': ('Total Backward Packets', 'Total Bwd Packets'),
    'fwd_bytes': ('Total Length of Fwd Packets', 'Total Length of Forward Packets'),
    'bwd_bytes': ('Total Length of Bwd Packets', 'Total Length of Backward Packets'),
    'dst_port': ('Destination Port', 'Dst Port'),
}


def _normalize_keys(row: dict) -> dict:
    return {str(k).strip().lstrip('\ufeff'): v for k, v in row.items() if k is not None}


def _field(row: dict, names: tuple[str, ...]) -> str:
    for name in names:
        if name in row and row[name] is not None:
            return str(row[name]).strip()
    raise ValueError(f'missing CICFlowMeter field; expected one of {names}')


def _finite_nonnegative(value: str, name: str) -> float:
    try:
        number = float(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(f'invalid CIC numeric value {name}') from exc
    if not math.isfinite(number) or number < 0 or number > 1e15:
        raise ValueError(f'invalid CIC numeric range {name}')
    return number


def feature_row(record: dict) -> dict:
    data = _normalize_keys(record)
    values = {name: _finite_nonnegative(_field(data, aliases), name)
              for name, aliases in CORE.items()}
    if values['dst_port'] > 65535 or not values['dst_port'].is_integer():
        raise ValueError('invalid destination port')
    duration_seconds = max(values['duration'] / 1e6, 1e-4)  # CICFlowMeter uses microseconds.
    total_bytes = values['fwd_bytes'] + values['bwd_bytes']
    total_packets = values['fwd_packets'] + values['bwd_packets']
    return {
        'log_duration': math.log1p(duration_seconds),
        'log_fwd_packets': math.log1p(values['fwd_packets']),
        'log_bwd_packets': math.log1p(values['bwd_packets']),
        'log_fwd_bytes': math.log1p(values['fwd_bytes']),
        'log_bwd_bytes': math.log1p(values['bwd_bytes']),
        'log_bytes_per_second': math.log1p(min(1e12, total_bytes / duration_seconds)),
        'log_bytes_per_packet': math.log1p(total_bytes / max(total_packets, 1)),
        'response_fraction': values['bwd_bytes'] / max(total_bytes, 1),
        'dst_port': values['dst_port'],
        'well_known_port': float(values['dst_port'] < 1024),
    }


def label_row(row: dict) -> tuple[int, str]:
    value = _field(_normalize_keys(row), ('Label', 'label')).strip()
    if not value:
        raise ValueError('CIC label empty')
    return (0 if value.casefold() == 'benign' else 1, value)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def load_cic_csv(path: Path, *, max_rows: int = 30000, seed: int = 42) -> tuple[list[dict], dict]:
    """Bounded reservoir sampling; row fingerprint is over features, never the label."""
    if not 100 <= max_rows <= 1000000:
        raise ValueError('max_rows must be between 100 and 1000000')
    rng = random.Random(seed)
    kept = []
    seen = dropped = 0
    with Path(path).open(newline='', encoding='utf-8-sig', errors='replace') as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError('CIC file has no header')
        for row in reader:
            try:
                features = feature_row(row)
                label, category = label_row(row)
            except ValueError:
                dropped += 1
                continue
            stamp = _normalize_keys(row).get('Timestamp', '').strip()
            # Only include timestamp if provided; no conversion that pretends it
            # is a precise globally synchronized capture clock.
            raw = json.dumps(features, sort_keys=True, separators=(',', ':'))
            item = {'features': features, 'label': label, 'attack_category': category,
                    'fingerprint': hashlib.sha256(raw.encode()).hexdigest(),
                    'timestamp_raw': stamp or None}
            seen += 1
            if len(kept) < max_rows:
                kept.append(item)
            else:
                idx = rng.randrange(seen)
                if idx < max_rows:
                    kept[idx] = item
    if not kept:
        raise ValueError('no valid CIC rows after finite-value and schema validation')
    return kept, {'path': str(path), 'sha256': _sha256(path), 'valid_rows': seen,
                  'skipped_invalid_rows': dropped, 'sampled_rows': len(kept),
                  'sampling': 'seeded reservoir' if seen > max_rows else 'all valid rows'}


def _unique(rows: list[dict], disallow: set | None = None) -> tuple[list[dict], int]:
    fingerprints = set(disallow or ())
    out = []
    for row in rows:
        if row['fingerprint'] in fingerprints:
            continue
        fingerprints.add(row['fingerprint'])
        out.append(row)
    return out, len(rows) - len(out)


def evaluate_cic(train_file: Path, independent_test_file: Path, *,
                 seed: int = 42, max_train: int = 25000, max_test: int = 15000,
                 quantile: float = .97) -> dict:
    """Fit/calibrate on train-benign, evaluate on independent supplied test file.

    Users must select disjoint capture days/sites for this independence claim.
    Published CSV metadata cannot itself prove those operational constraints.
    """
    if not .85 <= quantile <= .999:
        raise ValueError('invalid calibration quantile')
    if Path(train_file).resolve() == Path(independent_test_file).resolve():
        raise ValueError('train and independent test must be distinct file paths')
    train_rows, train_meta = load_cic_csv(train_file, max_rows=max_train, seed=seed)
    test_rows, test_meta = load_cic_csv(independent_test_file, max_rows=max_test, seed=seed + 1)
    train_rows, within_train_duplicates = _unique(train_rows)
    test_rows, test_duplicates = _unique(test_rows, {r['fingerprint'] for r in train_rows})
    benign = [r for r in train_rows if r['label'] == 0]
    rng = random.Random(seed)
    rng.shuffle(benign)
    split = int(.8 * len(benign))
    fitting, calibration = benign[:split], benign[split:]
    if len(fitting) < 80 or len(calibration) < 20 or len(test_rows) < 10:
        raise ValueError('not enough independent data after benign and duplicate filtering')
    vectorizer = DictVectorizer(sparse=False)
    x_fit = vectorizer.fit_transform([r['features'] for r in fitting])
    x_cal = vectorizer.transform([r['features'] for r in calibration])
    x_test = vectorizer.transform([r['features'] for r in test_rows])
    scaler = RobustScaler().fit(x_fit)
    x_fit, x_cal, x_test = scaler.transform(x_fit), scaler.transform(x_cal), scaler.transform(x_test)
    models = {
        'isolation_forest': IsolationForest(n_estimators=160, random_state=seed, n_jobs=1),
        'lof_novelty': LocalOutlierFactor(n_neighbors=min(25, len(fitting) - 1),
                                        novelty=True, n_jobs=1),
    }
    y_true = np.array([r['label'] for r in test_rows], dtype=int)
    results = {}
    for name, model in models.items():
        model.fit(x_fit)
        cal_scores = -model.decision_function(x_cal)
        scores = -model.decision_function(x_test)
        threshold = float(np.quantile(cal_scores, quantile))
        results[name] = metrics(y_true, scores, threshold)

    def rule(row):
        f = row['features']
        return (float(f['response_fraction'] < .02)
                + float(f['log_duration'] < math.log1p(.05))
                + float(f['dst_port'] >= 49152))
    cal_rules = [rule(row) for row in calibration]
    threshold_rule = float(np.quantile(cal_rules, quantile)) + 1e-6
    results['rule_based'] = metrics(y_true, np.array([rule(row) for row in test_rows]),
                                    threshold_rule)
    return {
        'benchmark': 'CIC-IDS2017-flowmeter-CSV',
        'source': 'https://www.unb.ca/cic/datasets/ids-2017.html',
        'dataset_provenance': {'train': train_meta, 'test': test_meta},
        'sample_counts': {'training_benign': len(fitting), 'calibration_benign': len(calibration),
                          'test': len(test_rows), 'test_attacks': int(y_true.sum())},
        'duplicate_removed': {'train': within_train_duplicates, 'test': test_duplicates},
        'independent_capture_verified': False,
        'true_chronological_validation_verified': False,
        'attack_categories_in_test': dict(Counter(r['attack_category'] for r in test_rows
                                                 if r['label'] == 1)),
        'features': vectorizer.feature_names_,
        'metrics': results,
        'limitations': [
            'Explicit independent train/test files are supplied by the operator; file disjointness alone does not prove capture or host independence.',
            'CICFlowMeter numeric schema is a benchmark feature space, not interchangeable with Zeek/Suricata production feature semantics.',
            'Benchmarks require real official CSVs for real-world results; synthetic test fixtures are never a substitute.',
            'No packet payloads are read or stored; timestamps and IP addresses are never invented.',
        ],
    }
