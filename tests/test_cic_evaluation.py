"""Fixture-only CIC contract regression tests; NEVER reported as real CIC accuracy."""
import csv

import pytest

from networkpulse.evaluation.cic import evaluate_cic, feature_row, label_row, load_cic_csv

FIELDS = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
          'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
          'Destination Port', 'Label']


def row(i, attack=False):
    return {'Flow Duration': str(1000 if attack else 500000 + i * 111),
            'Total Fwd Packets': str(1 if attack else 3 + i % 15),
            'Total Backward Packets': '0' if attack else str(2 + i % 7),
            'Total Length of Fwd Packets': str(4 if attack else 200 + i * 7),
            'Total Length of Bwd Packets': '0' if attack else str(500 + i * 11),
            'Destination Port': str(60000 if attack else [80,443,53,22][i % 4]),
            'Label': 'BENIGN' if not attack else 'FixtureAttack'}


def make_csv(path, records):
    with path.open('w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(records)


def test_cic_adapter_and_independent_synthetic_fixture_benchmark(tmp_path):
    tr, te = tmp_path / 'synthetic_train.csv', tmp_path / 'synthetic_test.csv'
    make_csv(tr, [row(i) for i in range(190)])
    make_csv(te, [row(i + 1000, attack=i >= 40) for i in range(75)])
    result = evaluate_cic(tr, te)
    assert result['sample_counts']['test_attacks'] > 0
    assert result['sample_counts']['test'] > 10
    assert 'isolation_forest' in result['metrics']
    assert 'lof_novelty' in result['metrics']
    assert 'rule_based' in result['metrics']
    assert result['independent_capture_verified'] is False
    assert result['true_chronological_validation_verified'] is False
    assert result['dataset_provenance']['train']['sha256']
    assert result['duplicate_removed']['test'] >= 0


def test_cic_rejects_invalid_and_same_file(tmp_path):
    assert label_row({'Label': 'BENIGN'}) == (0, 'BENIGN')
    assert feature_row(row(5))['well_known_port'] == 1
    with pytest.raises(ValueError, match='destination port'):
        feature_row({**row(1), 'Destination Port': '100000'})
    with pytest.raises(ValueError, match='missing'):
        feature_row({'Label':'BENIGN'})
    p=tmp_path/'fixture.csv'
    make_csv(p, [row(i) for i in range(120)])
    with pytest.raises(ValueError, match='distinct'):
        evaluate_cic(p,p)
    r, meta = load_cic_csv(p, max_rows=100)
    assert len(r) == 100
    assert meta['valid_rows'] == 120
    assert meta['sampling'] == 'seeded reservoir'
