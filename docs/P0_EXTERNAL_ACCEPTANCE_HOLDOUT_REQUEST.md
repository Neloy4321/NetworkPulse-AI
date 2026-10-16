# P0 Operational ML acceptance — external data and deployment evidence request

**Current decision: NO-GO.** This checklist is for acquiring *future* evidence,
not instructions to reinterpret previously exposed development captures as virgin.

## What exists and what it proves

- PR #25: SHA-pinned private Cloudflare R2 source acquisitions and
  fail-closed source-dependent CI.
- PR #26: source-only feature audit and four-fold capture-diverse
  RandomForest research. In 4-fold UNSW LOCO, the v1 RF observed benign
  FPR 0.83–2.54% and attack recall 96.52–99.52%; all four folds met
  the numerical gate. This is only **one controlled cyber range**,
  with shared hosts and previously exposed capture parts. It does
  **not** certify a production model.
- No reviewed frozen/deployable RF model package exists yet; the shipped
  native IsolationForest remains unchanged. A source model's research
  metrics cannot establish the shipped detector's behavior.

## What is needed for independent ML acceptance

Before receiving or opening target data, record and review:
1. A **single, frozen model artifact** with verified SHA-256, serialized
   preprocessing/feature-contract version, immutable training ledger,
   deterministic training/code/dependency manifest, and reviewer record.
   Fix the threshold and reference performance requirements **before
   inspecting** independent target labels.
2. The source training ID ledger and normalized flow fingerprints.
   Cross-adapter duplicate rejection must run before scoring.
3. Target source and label origin, site operator approval, capture time
   coverage and schema. The target network must be independently operated
   from UNSW/TON training and genuinely separate. Do not misrepresent
   lab datasets as deployed customer sites.
4. Independently adjudicated **benign and attack labels** for every
   evaluated flow, with documented detection taxonomy and handling for
   ambiguous/unknown events. A malware-family name or IoT label rule
   is not automatically equivalent to native anomaly ground truth.
5. Prefer multiple capture days, differing benign workloads and attack
   types and naturally occurring prevalence. Minimum thresholds in
   `ExternalHoldoutSpec` are *implementation floors*, not proof of
   statistical power. Count distinct hosts, correlated sessions and
   actual analyst false-alert workload without exporting identifiers.
6. Evaluate frozen model **once**, without using target labels to
   adjust features, thresholds, resampling, training, or candidate choice.
   Require benign FPR **95% Wilson upper ≤5%** and attack recall
   **95% Wilson lower ≥80%** plus per-day/site evidence. Flow correlation
   can make Wilson bounds optimistic.
7. Prove the **same exact signed active model and feature pipeline** run
   in a controlled deployed application, verify model artifact signature,
   TLS/secret hygiene, alert latency, resource SLOs, false alerts per
   operational time window, and real independent operator review.
   A passing offline experiment alone cannot satisfy operational acceptance.

## Data format (restricted, non-public)

Accepted future testing input: properly authorized, labeled real flow
records with UTC timestamps, source/destination IP and port, protocol,
duration, directional byte/packet counters, documented connection state,
and benign/attack ground truth. Ingest through a verified Zeek, Suricata
or canonical adapter; reject missing/misinterpreted native fields rather
than inventing values. Process addresses/IDs only in protected compute;
publish only aggregate evidence. Do **not** add network captures, raw
IP records, API tokens or `joblib` files from untrusted parties to the
public GitHub repository.

Record cryptographic SHA-256 digests and exact source bytes in a private
manifest; do not treat multipart S3 ETags as SHA-256. Freeze and register
the independent source before running its evaluation.

## Additional research-only alternative (not production site)

Stratosphere Laboratory's official
[IoT-23 dataset](https://www.stratosphereips.org/datasets-iot23)
publishes `bro/conn.log.labeled` Zeek-format network flows from infected
and benign IoT device scenarios with documented expert/rule-assisted
labels. Individual scenario downloads avoid the full 8.8GB/21GB
archives. See official licensing and source rules before acquisition.
A legitimately untouched IoT-23 capture may serve as a **second
laboratory-family external research test**, with schema verification and
label mapping agreed *before target scoring*. It is **not** a production
SOC deployment and cannot alone make NetworkPulse operationally accepted.

The already examined TON `Network_dataset_23.csv` and all four UNSW
raw captures are **development/exposed evidence** and no longer qualify
as a virgin target for model selection or acceptance.
 
## Security hardening required independently

The original R2 Access Key ID and Secret Access Key were previously
posted in a chat. Rotate/revoke them and use a **new read-only,
bucket-scoped CI credential** with no `CreateBucket` or `PutObject`
permission. Secrets belong in GitHub Actions settings, never commits,
test logs, result JSON, source code or operator screenshots.

## Honest handoff condition

Until target provenance/consent, an immutable reviewed model, a training
ledger and an actual deployment are all available, record **P0 NO-GO**.
Do not merge draft research PRs under a claim that operational ML
acceptance is passed, or lower previously declared numeric thresholds.
