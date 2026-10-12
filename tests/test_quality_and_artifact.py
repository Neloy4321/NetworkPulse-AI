from dataclasses import replace

import pytest

from networkpulse.api import create_app
from networkpulse.data_quality import fingerprint, quality_report, write_quality_report
from networkpulse.model_registry import sha256


def test_quality_provenance_and_duplicates(samples, tmp_path):
    records = samples[:50] + [samples[3], samples[4]]
    first = quality_report(records)
    assert first['record_count'] == 52
    assert first['duplicate_count'] == 2
    assert first['sources']['simulator'] == 52
    assert first['feature_contract'] == 1
    with pytest.raises(ValueError, match='at least one'):
        quality_report([])
    path = tmp_path / 'flows.jsonl'
    path.write_text('\n'.join(x.model_dump_json() for x in records) + '\n')
    report = write_quality_report(records, path, tmp_path / 'report.json')
    assert report['source_sha256'] == fingerprint(path)
    assert (tmp_path / 'report.json').is_file()


def test_configured_model_checksum_fails_closed(app_settings):
    good = replace(app_settings, model_sha256=sha256(app_settings.model_path))
    create_app(good)
    with pytest.raises(ValueError, match='SHA-256'):
        create_app(replace(app_settings, model_sha256='a' * 64))
