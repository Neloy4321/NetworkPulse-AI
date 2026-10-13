# v0.4 Synthetic-first implementation — evidence ledger

The user will provide labeled real traffic / official benchmark files later. **No missing real-world dataset is fabricated**. All quantitative detector scores in the stock dashboard come from seeded synthetic records. `100% implemented` must not be inferred from any roadmap percentages: training data and infrastructure evidence are separate gates.

| User requirement | Shipped engineering slice | Evidence / remaining external validation |
| --- | --- | --- |
| 1. Real dataset & ML validation | External UNSW CSV adapter (train/test separation, IF/LOF/rule baselines, PR-AUC, ROC-AUC, FPR, category recall, duplicate filtering), synthetic chronological detector tests | Official UNSW CSVs not provided; no actual external benchmark run, time/site shift validation or confirmed real-data accuracy |
| 2. Database | Alembic 0001–0003, PostgreSQL BIGINT, atomic ingestion, duplicate contention, SQLite backup, conservative manual archival with SHA-256 | CI PostgreSQL test; production scale, archival encryption/PITR/retention automation not verified |
| 3. Identity/security | Opt-in OIDC RS256/RBAC for API, API-key local mode, body size and in-process rate limiter, security headers, JWT negative tests | No deployed real IdP, browser PKCE, gateway TLS, central secrets or penetration test; browser API key prompt is a demo workflow |
| 4. Streaming | Zeek/Suricata JSONL collector, checkpoint, Redis Streams, worker, retry/DLQ/claim, CI Redis test | No physical sensor field deployment, HA worker failover benchmark or measured live processing SLO |
| 5. ML lifecycle | PSI drift, budget, local candidate registry, SHA-256 integrity, metadata gates, shadow comparison and manual promotion/rollback | Synthetic comparison only; artifact signature/trusted attestation, delayed labels, distributed model-serving gates absent |
| 6. Operational monitoring | Prometheus counters/histograms and optional Grafana dashboards | Configuration not verified with actual Docker Compose run; no lag paging, tracing or managed alert manager |
| 7. SOC | Filter/sort/paginate, secure role gates, alert detail, case notes, assignment, actor-attributed history, CSV export | Complete browser UI for all case endpoints, SSO UX and automated E2E not verified |
| 8. QA | SQLite, concurrency, migration, OIDC negative, registry, retention, SOC tests; CI PostgreSQL/Redis services | Browser Playwright and stress/penetration scans not independently run |
| 9. Deployment | Dockerfile, Compose PostgreSQL/worker; GH Actions tests and migrations | Multi-stage signed images, actual staging HTTPS, disaster recovery drill unverified |
| 10. Network intelligence | Windowed host behavior and multi-flow correlation with conservative heuristic labels | Asset inventory and reputable feed enrichment not implemented |
| 11. Data/MLOps | Benchmark file checksums, versioned feature contract, shadow candidate registry, drift | End-to-end immutable dataset lineage, signed artifacts, scheduled runs and large-scale partitioned storage missing |
| 12. Documentation | Architecture, API, threat model, benchmark notes, migration, retention, model lifecycle, observability | Actual official benchmark report, reproducible measured load and short demo video pending |

**Scope of local test:** Python tests exercise the actual source code. Service-dependent PostgreSQL and Redis tests run on GitHub Actions when the associated workflow completes; check the run result rather than assuming passing local tests imply passing CI.

To upgrade a v0.1/v0.2 SQLite DB, stop the old API, back up `data/networkpulse.db`, install v0.4 into a separate directory or Git checkout, copy your **existing data/ directory**, run `networkpulse db upgrade`, then run `networkpulse bootstrap` and restart the API. Do not overwrite the only original model or SQLite database.

## v0.5 additions (synthetic-first)

- A **separate CIC-IDS2017 FlowMeter CSV evaluation adapter** joins the UNSW prepared-CSV benchmark path (official files still not supplied).
- Canonical flow quality and SHA-256 provenance reporting.
- Offline asset inventory and operator-vetted indicator enrichment (no automatic blocking, real feed not authenticated).
- Optional serving/worker trusted model SHA-256 pinning.
- Multi-stage container recipe, TLS/OIDC reverse-proxy **example**, and scheduled pip-audit workflow definition.

No actual real-world detection measurements, HTTPS staging deployment, or browser OIDC login results have been produced by these additions. Complete engineering scope and real-world evidence remain separate.


## Automated browser end-to-end smoke (2026-10-13 update)

`.github/workflows/browser-e2e.yml` now provisions Chromium in GitHub Actions,
creates a disposable synthetic model/SQLite database, boots a local FastAPI
server and verifies that the real browser starts with **All** alert filters,
loads 325 synthetic holdout flows, renders the alerts table, changes a filter,
restores the default and remains operational at mobile width. The test checks
that the browser does not send empty optional filters and does not receive a
non-200 alert query. This is a regression check, not a production browser
compatibility matrix or a penetration test.
