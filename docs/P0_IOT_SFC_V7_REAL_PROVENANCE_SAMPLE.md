# IoT-SFC v7 — P0 Authentic Row Provenance Sample (no model scoring)

## User-confirmed permission

On 2026-10-23 the dataset downloader reported directly contacting the dataset
rights holders and receiving **research use permission conditional on proper
citation**. This is a user-reported permission statement, **not** a published
license grant or independently inspected written email. Cite the original
dataset record as [IoT-SFC v2, Zenodo 23371775](https://zenodo.org/records/23371775)
in all research reports, with the publisher's preferred authors/title/year and
DOI checked against its official citation. This workflow does not redistribute
original data; GitHub Actions temporarily retrieves the publicly accessible
source ZIP, computes aggregated source metadata, and deletes raw bytes.

Do NOT extrapolate user-reported research permission to training on private
production telemetry, public redistribution of third-party records, or a
commercial license without explicit support.

## Frozen model and preregistration

The **existing** unsigned source-calibrated V2 RF candidate SHA-256
`cd239783fd4318c0c4e897f1d451c2d5af4b42132979c79a4e489df626f538a5`
and cutoff `0.20` are unchanged. This step does not load that model at all.
The IoT-SFC ZIP SHA-256 is pinned to
`070b1356e5bd296e584109fae79139cfe0f20ff4790f69e42994d67362cb9f62`.

The dataset header alone was already inspected and pinned in
[P0_IOT_SFC_V2_VERIFIED_HEADER_EVIDENCE.json](P0_IOT_SFC_V2_VERIFIED_HEADER_EVIDENCE.json).
This step *intentionally begins target metadata/label unblinding* to qualify
the flow source after the model/threshold were preregistered; all future reports
must mark this 100k positional first-row sample as **exposed to analysis**,
not a virgin target distribution.

## Genuine audit in GitHub Actions

Workflow: `.github/workflows/p0-iot-sfc-v7-provenance.yml`.

- Fetch original official record ZIP on an isolated ephemeral CI runner.
  Verify the full ZIP byte length (776500807) and original pinned SHA-256
  before any decompression.
- Stream a **maximum of first 100,000 CSV records in archive order** from
  the ZIP without extracting the full 13.56 GB member.
- Check source event kind labels against **literal** `conn.log` only.
  Classify other Zeek/DNS/HTTP/MQTT event categories as excluded; unknown
  categories go in an aggregate unknown bucket with no raw source names.
- Check candidate **producer** `attack` literal binary 0/1,
  `type_of_attack` presence, `label_source` and `window_id` presence.
  Preserve the difference between **producer assertion** and independently
  validated ground truth. Record no raw attack family names or window keys.
- For strict `conn.log` records check field conversion under the existing
  versioned V2 adapter; aggregate invalid identity/counter reasons and
  missingness. No model scoring occurs.
- Aggregate per-UTC-day support of syntactically valid connection candidates
  only; dates are not an operational independent site/day proof.
- No IP, UID, payload, record, model artifact, or raw labels are saved or
  uploaded. The workflow explicitly removes the whole ZIP and uploads only
  a small JSON aggregate for internal analysis.
- This positional first-100k sample is **not representative** of all
  42M records and is NOT a full train/holdout leakage review, label audit
  or performance benchmark.

## Next conditional gates

If the authentic sample finds `log_type` is not exactly `conn.log`, or
`attack` not literal 0/1, **do not silently change interpretation**.
Review official data dictionary and original Zeek/label derivation first, then
publish a versioned no-tuning adapter amendment BEFORE actual scoring.

If eligible flows and producer labels exist, perform an independent label,
attack-session timing/direction and train/holdout leakage audit using the
full original labelled source with multi-day, per-family support. A producer's
session metadata cannot be described as independent human-verified labels.

Only then run one frozen SHA/threshold evaluation; minimum 200 benign,
100 attack and 3 days, plus Wilson FPR 95% upper <= 5%, recall 95% lower >=80%
and per-day/cluster-aware alarm quality. If it fails, report research
**NO-GO** rather than tune on the same target or claim ML acceptance.
A good public-lab result still does not equal a signed field SOC deployment
and independent operational reviewer approval.
