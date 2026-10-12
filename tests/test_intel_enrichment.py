import csv

import pytest

from networkpulse.intel_enrichment import enrich_flow, load_assets, load_indicators


def csv_file(path, rows):
    with path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def test_offline_enrichment_assets_and_indicators(tmp_path, samples):
    e = samples[0]
    ip, dest = str(e.src_ip), str(e.dst_ip)
    inventory = tmp_path / 'assets.csv'
    csv_file(inventory, [{'ip': ip, 'asset_id': 'workstation-1', 'owner': 'local-lab',
                          'criticality': 'medium'}])
    feed = tmp_path / 'feed.csv'
    csv_file(feed, [{'ip': dest, 'feed_name': 'fixture-not-a-real-feed',
                     'collected_utc': '2026-10-12T12:00:00Z',
                     'reference': 'https://example.org/fixture'}])
    report = enrich_flow(e, load_assets(inventory), load_indicators(feed))
    assert report['source_asset']['asset_id'] == 'workstation-1'
    assert report['indicator_matches'][0]['direction'] == 'destination'
    assert 'never auto-block' in report['disclaimer']
    csv_file(inventory, [{'ip': 'bad-ip', 'asset_id': 'bad', 'owner': 'foo',
                          'criticality': 'low'}])
    with pytest.raises(ValueError):
        load_assets(inventory)
    csv_file(feed, [{'ip': dest, 'feed_name': 'fixture',
                     'collected_utc': '2026-10-12T12:00:00',
                     'reference': 'http://wrong.example'}])
    with pytest.raises(ValueError, match='timezone'):
        load_indicators(feed)
