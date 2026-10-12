"""Optional offline asset and threat-indicator enrichment.

No network calls, claims of maliciousness, or third-party attribution. Input
must be trusted and independently licensed by the deployment operator.
"""
from __future__ import annotations

import csv
import ipaddress
from datetime import datetime, timezone
from pathlib import Path


def load_assets(path: Path) -> dict[str, dict]:
    """Inventory CSV: ip,asset_id,owner,criticality. Duplicate IPs refused."""
    assets = {}
    with Path(path).open(newline='', encoding='utf-8-sig') as fh:
        reader = csv.DictReader(fh)
        if not {'ip', 'asset_id', 'owner', 'criticality'} <= set(reader.fieldnames or []):
            raise ValueError('asset inventory schema missing ip,asset_id,owner,criticality')
        for index, row in enumerate(reader, 2):
            ip = str(ipaddress.ip_address(row['ip'].strip()))
            if ip in assets:
                raise ValueError(f'duplicate asset address at row {index}')
            name = row['asset_id'].strip()
            if not name or len(name) > 100 or len(row['owner']) > 100:
                raise ValueError('invalid asset identifier or owner')
            criticality = row['criticality'].strip().lower()
            if criticality not in {'low', 'medium', 'high', 'critical'}:
                raise ValueError('asset criticality must be low, medium, high, critical')
            assets[ip] = {'asset_id': name, 'owner': row['owner'].strip(),
                          'criticality': criticality}
    return assets


def load_indicators(path: Path) -> dict[str, dict]:
    """Offline indicator CSV: ip,feed_name,collected_utc,reference.

    This never verifies third-party assertions; feed provenance must be audited.
    """
    result = {}
    with Path(path).open(newline='', encoding='utf-8-sig') as fh:
        reader = csv.DictReader(fh)
        if not {'ip', 'feed_name', 'collected_utc', 'reference'} <= set(reader.fieldnames or []):
            raise ValueError('indicator CSV schema invalid')
        for row in reader:
            address = str(ipaddress.ip_address(row['ip'].strip()))
            stamp = datetime.fromisoformat(row['collected_utc'].strip().replace('Z', '+00:00'))
            if stamp.tzinfo is None:
                raise ValueError('indicator timestamp must have timezone')
            if not row['reference'].startswith('https://'):
                raise ValueError('indicator reference must use HTTPS')
            if not row['feed_name'].strip() or len(row['feed_name']) > 100:
                raise ValueError('invalid feed name')
            result[address] = {'feed_name': row['feed_name'].strip(),
                               'collected_utc': stamp.astimezone(timezone.utc).isoformat(),
                               'reference': row['reference'].strip()[:500]}
    return result


def enrich_flow(event, assets: dict, indicators: dict) -> dict:
    src, dst = str(event.src_ip), str(event.dst_ip)
    matches = []
    for direction, address in [('source', src), ('destination', dst)]:
        if address in indicators:
            matches.append({'direction': direction, 'ip': address, **indicators[address]})
    return {'event_id': event.key(), 'source_asset': assets.get(src),
            'destination_asset': assets.get(dst), 'indicator_matches': matches,
            'disclaimer': 'External indicator matches are unverified hints; never auto-block solely on this result.'}
