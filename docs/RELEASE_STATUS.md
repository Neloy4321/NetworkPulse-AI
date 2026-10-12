# Evidence-led engineering status — v0.3 development

The following is the checklist status after the v0.2 database release and first set of v0.3 enhancements. A working module or test is **not** proof that its entire requirement has been completed.

| Requirement | Status | Verified implementation | Important gaps |
| :--- | :--- | :--- | :--- |
| 1. Real-data ML evaluation | **Partial** | External UNSW CSV adapter, IF/LOF/rules and metrics, duplicate-leakage tests on synthetic fixtures | Official-file evaluation report, CIC mapping, temporal/source shift and unseen-site validation |
| 2. Database correctness | **Strong partial** | Alembic, BIGINT PG, atomic upserts, contention tests | Retention/archival jobs, staged DB rollback, throughput |
| 3. Security & authorization | **Partial** | Local API keys + opt-in OIDC RS256 RBAC, negative tests | Real IdP deployment, frontend login/PKCE, rate limits, TLS, secure actor audit |
| 4. Continuous processing | **Partial** | Redis Streams worker, collector, checkpoints, retries, backpressure and DLQ; CI Redis test | Actual Zeek/Suricata sensor deployment, multi-node failover, latency benchmarks |
| 5. Reliable ML & lifecycle | **Partial** | Synthetic temporal evaluation, PSI drift reporting, alert budget | Model registry, signed artifacts, trained candidate gates, shadow & rollback |
| 6. Monitoring | **Partial** | JSON request metrics, Prometheus-format counters/histograms | Grafana, distributed tracing, SLOs and operational paging |
| 7. SOC workflow | **Partial** | Investigation triage and audit, severity/IP filtering, pagination, sort | Case ownership, detailed timeline, export, OIDC browser UX |
| 8. Tests & QA | **Partial** | Python unit/integration tests, PG/Redis service CI, JWT negative tests | Browser E2E (local browser blocked), load/penetration tests, fuzzing |
| 9. Deployment & DevOps | **Partial** | Compose Postgres+opt-in Redis worker, nonroot image, CI | Docker build runtime proof, TLS staging, rollback drills and image scans |
| 10. Network intelligence | **Partial** | Windowed per-source behavior and scanning-like metadata heuristics | Asset inventory, multievent correlation, threat feeds |
| 11. Data & MLOps | **Partial** | Explicit feature contract, benchmark provenance SHA256, PSI monitoring | Candidate registry, artifact signatures, partitioned telemetry and scheduled reports |
| 12. Documentation | **Partial** | Model card, architecture, security threat model, benchmark/runbooks, CI | Official benchmark results, measured load tests, validated production demo and video |

**Important:** The official benchmark files are not redistributed; licensing/academic-use conditions are linked in `REAL_DATA_BENCHMARK.md`. Do not quote synthetic fixture test results as real-world accuracy.
