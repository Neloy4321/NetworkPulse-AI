# Model Card — NetworkPulse Isolation Forest v1

## Intended task

Rank network flow-metadata observations by how unusual their feature patterns appear relative to a fitted benign baseline. The output is for **human triage prioritization**, not automated intrusion prevention, threat attribution or legal/security incident confirmation.

## Algorithm and data

- Model: `sklearn.ensemble.IsolationForest`, 180 estimators, fixed seed, `contamination='auto'`.
- Encoding: `DictVectorizer` trained on training-window flows, with deterministic log-scaled numeric features and one-hot protocol/state flags.
- Data: **seeded synthetic metadata** by default. No real sensor data is distributed in the demo artifact.
- Split: chronological 60% benign-fit / 15% benign-threshold calibration / 25% held-out evaluation.
- Threshold: 97th percentile of *benign calibration* anomaly scores. Later labels are only used for reporting quality metrics, not fitting or threshold selection.

## Reproduction record

Command: `networkpulse bootstrap --count 1300 --seed 42` (locally executed October 2026)

| Audit item | Observed value |
| :--- | ---: |
| Train rows | 780 |
| Calibration rows | 195 |
| Holdout rows | 325 |
| Synthetic anomalies injected in holdout | 50 |
| Flagged holdout rows | 66 |
| Precision | 0.7576 |
| Recall | 1.0000 |
| F1 | 0.8621 |
| ROC AUC | 1.0000 |
| Average precision | 1.0000 |

**The dataset construction is intentionally easy to separate.** The 1.0 ranking metrics must not be read as evidence of a deployable intrusion detector. These results only confirm that the training/evaluation code and simulated outliers work reproducibly on the included synthetic generator.

## What the scores mean

- `anomaly_score`: `-decision_function` from Isolation Forest. Larger scores indicate stronger deviation from the training distribution.
- `threshold`: anomaly-score quantile estimated on a **different** benign-only calibration window.
- `anomalous`: anomaly score at or above threshold.
- `risk` (0–100): **relative display index**, not maliciousness probability. Tiers are operational UI conventions, not threat intelligence.
- `reasons`: non-model heuristic indicators such as missing response packets, very short duration, unusual port and connection state. These are not feature-attribution explanations of the IF model.

## Principal limitations

1. **Domain shift:** Synthetic flow features do not capture operational network distributions.
2. **False positives:** Maintenance, backups, scans and bursty services can look unusual while remaining authorized.
3. **Sensor semantic mismatch:** Zeek `conn_state` and Suricata `flow.state` are different vocabularies; blended training needs explicit mapping or per-sensor models.
4. **Temporal dependence:** Flows from the same host/service can be correlated across time; chronological evaluation alone does not guarantee cross-site generalization.
5. **Feature scope:** No packet payloads, host process data, reputation feeds, graph topology, online drift response or per-entity baselines.
6. **No ground-truth assertions:** The model produces investigation candidates, not verified security incidents.

## Required before production operations

- Obtain authorized, independently labeled traffic datasets with documented collection period and sensor versions.
- Establish realistic false-positive costs and a human-review capacity budget.
- Run site/time-separated baselines, stratified performance slices and bootstrapped uncertainty intervals.
- Compare Isolation Forest to simple rules and supervised baselines without test leakage.
- Add drift detection, change management, authenticated access, retention/deletion policy, provenance and privacy reviews.

## Reproducibility and artifact safety

Model artifacts are not checked into Git because they can be regenerated. Joblib artifacts are pickle-based: **never load untrusted user-provided artifacts**. The detector checks the schema feature version after deserialization, but that check is not a sandbox or signature verification.
