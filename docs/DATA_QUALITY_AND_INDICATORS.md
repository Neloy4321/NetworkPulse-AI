# Dataset quality / offline asset enrichment

Use existing canonical example data or an authorized canonical JSONL file:

```powershell
networkpulse generate-demo --count 1300 --seed 42 --output examples/generated-demo.jsonl
networkpulse audit-data --data examples/generated-demo.jsonl --output reports/data-quality.json
```

The quality report includes SHA-256 file provenance, schema/feature contract version, timestamps, duplicate event count, origin/protocol/label distributions and IP cardinality. It checks metadata consistency, **not** truth of labels or external dataset provenance.

Opt-in offline enrichment requires **separate, trusted operator-supplied CSV files**:

- `assets.csv`: `ip,asset_id,owner,criticality` (criticality one of low/medium/high/critical).
- `indicators.csv`: `ip,feed_name,collected_utc,reference` with timezone-aware time and HTTPS reference. The feed provider must be assessed for credibility, timeliness and redistribution rights by the operator.

```powershell
networkpulse enrich-offline --format zeek --data examples/zeek-conn.jsonl --assets path/to/assets.csv --indicators path/to/indicators.csv --output reports/enrichment.json
```

The application does not fetch threat feeds or automatically blacklist traffic. Indicator matching is **context**, never proof of compromise. The report contains potentially private IP/ownership data; store and share it securely. Not all synthetic demo IPs correspond to real assets.

Model artifact verification (optional fail-closed): Set `MODEL_SHA256` to the trusted 64-digit SHA-256 of the model artifact. API startup and worker startup will reject a mismatched artifact before deserialization. Only trusted, locally created artifacts should be loaded. This is integrity, **not signature-based provenance attestation**.
