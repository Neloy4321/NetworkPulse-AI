from pathlib import Path

import pytest

from networkpulse.detector import train
from networkpulse.model_registry import ModelRegistry, sha256
from networkpulse.simulator import sample_flows


def test_registry_gates_integrity_shadow_promotion_rollback(tmp_path):
    events = sample_flows(200, seed=4)
    first = train(events, seed=4, source='seeded_synthetic_demo')
    other = train(events, seed=19, source='seeded_synthetic_demo')
    a, b = tmp_path / 'a.joblib', tmp_path / 'b.joblib'
    first.save(a)
    other.save(b)
    registry = ModelRegistry(tmp_path / 'registry')
    with pytest.raises(ValueError, match='failed'):
        registry.register('bad', a, min_f1=1.0, max_alert_fraction=.01)
    assert registry.status()['candidates'] == {}
    data = registry.register('baseline', a)
    assert data['synthetic_only']
    registry.register('candidate', b)
    with pytest.raises(ValueError, match='already'):
        registry.register('candidate', b)
    deployed = tmp_path / 'live.joblib'
    assert registry.promote('baseline', deployed)['active'] == 'baseline'
    assert sha256(deployed) == sha256(a)
    shadow = registry.shadow('candidate', deployed, events[-50:])
    assert shadow['events'] == 50
    assert registry.promote('candidate', deployed)['previous'] == 'baseline'
    assert registry.rollback(deployed)['active'] == 'baseline'
    assert sha256(deployed) == sha256(a)
    (registry.root / 'candidate.joblib').write_bytes(b'corrupted')
    with pytest.raises(ValueError, match='integrity'):
        registry.promote('candidate', deployed)


def test_registry_invalid_name_and_missing_previous(tmp_path):
    registry = ModelRegistry(tmp_path / 'registry')
    with pytest.raises(ValueError, match='unknown'):
        registry.promote('x', tmp_path / 'active.joblib')
    with pytest.raises(ValueError, match='previous'):
        registry.rollback(tmp_path / 'active.joblib')
    with pytest.raises(ValueError, match='name'):
        registry.register('../escape', Path('none'))
