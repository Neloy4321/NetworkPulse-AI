# API & CLI Cookbook

Start the service according to [Quick start](../README.md#quick-start). These requests use flow metadata only.

## Authentication

Use the environment variable `NETWORKPULSE_API_KEY`, ideally generated using Python `secrets`. For an authenticated request:

```bash
curl -sS http://127.0.0.1:8000/api/v1/summary
```

## Ingest a canonical event

```bash
curl -X POST 'http://127.0.0.1:8000/api/v1/ingest' \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $NETWORKPULSE_API_KEY" \
  -d '{"events":[{
        "timestamp":"2026-01-01T00:10:00+00:00",
        "source":"canonical",
        "src_ip":"10.0.0.15","dst_ip":"172.16.10.5",
        "src_port":51929,"dst_port":443,"proto":"tcp",
        "duration":1.73,"orig_bytes":991,"resp_bytes":4830,
        "orig_pkts":10,"resp_pkts":13,"conn_state":"sf"
      }]}'
```

## Replay an authorized JSONL file over HTTP

```bash
networkpulse replay --path examples/zeek-conn.jsonl \
  --format zeek --url http://127.0.0.1:8000 \
  --batch-size 2 --delay 0.25
```

### Other query examples

```bash
curl 'http://127.0.0.1:8000/api/v1/events?limit=20&anomalies_only=true'
curl 'http://127.0.0.1:8000/api/v1/alerts?status=open'
curl 'http://127.0.0.1:8000/api/v1/trends'
curl 'http://127.0.0.1:8000/api/v1/model'
```

## Triage alert with an audited state transition

```bash
curl -X PATCH 'http://127.0.0.1:8000/api/v1/alerts/1' \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $NETWORKPULSE_API_KEY" \
  -d '{"status":"investigating","note":"Checking source and approved maintenance window"}'

curl 'http://127.0.0.1:8000/api/v1/alerts/1/history'
```

The mutation rejects missing/invalid API keys and notes shorter than three characters. Audit records include status before/after, reviewer note and timestamp. For the full OpenAPI schema visit `/docs` when the local app is running.
