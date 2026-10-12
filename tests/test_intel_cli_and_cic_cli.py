import csv
import json

from networkpulse.cli import main


def test_offline_enrichment_cli(tmp_path, capsys):
    from pathlib import Path
    root=Path(__file__).resolve().parents[1]
    zeek=root/'examples/zeek-conn.jsonl'
    import json as _json
    first=_json.loads(zeek.read_text().splitlines()[0])
    src=first['id.orig_h']
    dst=first['id.resp_h']
    assets=tmp_path/'assets.csv'
    with assets.open('w',newline='') as h:
        w=csv.DictWriter(h,fieldnames=['ip','asset_id','owner','criticality'])
        w.writeheader()
        w.writerow({'ip':src,'asset_id':'demo','owner':'fixture','criticality':'low'})
    feeds=tmp_path/'feeds.csv'
    with feeds.open('w',newline='') as h:
        w=csv.DictWriter(h,fieldnames=['ip','feed_name','collected_utc','reference'])
        w.writeheader()
        w.writerow({'ip':dst,'feed_name':'test-only','collected_utc':'2026-01-01T00:00:00Z','reference':'https://example.org'})
    output=tmp_path/'enrichment.json'
    assert main(['enrich-offline','--data',str(zeek),'--format','zeek','--assets',str(assets),
                 '--indicators',str(feeds),'--output',str(output)])==0
    result=json.loads(output.read_text())
    assert result['events_evaluated']==2
    assert result['items'][0]['source_asset']['asset_id']=='demo'
    assert result['source_sha256']
    assert 'events_evaluated' in capsys.readouterr().out
