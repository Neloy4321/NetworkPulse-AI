# P0 IoT-SFC v2 — Model Freeze and CSV-Blind Preregistration (2026-10-23)

**Status: PREREGISTERED_NOT_SCORED. ML P0 Operational Acceptance: NO-GO.**

Machine-readable, tested, pinned research protocol:
[P0_IOT_SFC_V2_FROZEN_PREREGISTRATION.json](P0_IOT_SFC_V2_FROZEN_PREREGISTRATION.json).

## Verified before preregistration

- Previously generated, **unsigned research-only V2 source-calibrated RandomForest** from GitHub Actions run 38909855312. The original Actions artifact 12050072139 was downloaded and member research-only-v2-calibrated.joblib SHA-256 independently hashed without unpickling: cd239783fd4318c0c4e897f1d451c2d5af4b42132979c79a4e489df626f538a5.
- Source calibration manifest from artifact 12049488464 was separately retrieved, with protocol SHA-256 3810aeb3f9510e2b6e736923ec7a44798fad9d37a56e3d27140c15a0f37fcfde, threshold 0.20, feature contract missingness_aware_flow_v2, 41,670 FIT and 5,026 CAL source flows. These metrics are *not* independent holdout evidence.
- User-run local iot_dataset_v7.zip **metadata-only** report: byte length 776,500,807, official Zenodo MD5 match 6b858e337a8241b89f4d76f9a1454a60, user-calculated SHA-256 070b1356e5bd296e584109fae79139cfe0f20ff4790f69e42994d67362cb9f62. One ZIP member iot_dataset_v7.csv; declared uncompressed 13,561,863,941 bytes.
- Google Drive connector cannot independently download this 776 MB file due to its 256 MiB limit. ZIP member CRC/payload have **not** been verified.
- The accompanying all_attacks_logs.json attack session schedule **was already examined**. CSV headers, per-flow labels and model predictions have **not been inspected** here. This is a partially exposed metadata but CSV-blind **public laboratory** dataset; not an untouched independently operated production field site.

## Immutable selection and result gates

Freeze the above original model SHA, immutable source protocol SHA and decision threshold **0.20**. Do **not** train, select features/models, change cutoff or calibrate using IoT-SFC labels. Prior calibration and exposed IoT-23 results, including earlier 43% benign FPR on a different laboratory test, stay documented failures; the existing candidate might fail this new target too.

Before scoring: verify proper dataset license, original ZIP bytes and CRC, per-flow label provenance, Zeek/Suricata canonical connection-flow feature semantics, capture timestamps, and zero overlap with training ledger. Mixed HTTP/DNS/connection log rows MUST NOT silently be scored as identical connection records. Ambiguous attack timestamps, synthetic scenario labels and missing ground truth are not independently adjudicated field labels; flag and review rather than invent labels.

**Research numerical gate**: >=200 authentic benign flows, >=100 authentic attack flows, >=3 eligible distinct capture days; 95% Wilson benign FPR **upper <=5%**, attack Recall **lower >=80%**, verified per-day and attack-family metrics, cluster-aware uncertainty assessment, zero train/target overlap, and observed false alerts per day. If insufficient support, unsupported schema or unverifiable provenance: BLOCKED. If numerical quality fails: RESEARCH NO-GO. Never suppress an unfavorable attack or benign subgroup. After labels are examined once, the current target becomes *exposed* and cannot be treated as a virgin retest.

Passing these laboratory gates STILL DOES NOT provide field operator ground truth, real signed deployment, HTTPS/OIDC parity, genuine workload or independent human approval. **P0 operational ML acceptance remains NO-GO.**

## Pre-score identity validation

Run this from repository root, with user preflight JSON plus secure local copies of the original model/manifest:

    python -m networkpulse.evaluation.iot_sfc_preregistration \
      --archive-preflight /private/networkpulse_iot_sfc_zip_preflight.json \
      --model /private/research-only-v2-calibrated.joblib \
      --manifest /private/v2-source-calibration.json \
      --report /private/iot-sfc-prescore-lock.json

The verifier streams model bytes for SHA-256, validates frozen manifest and protocol SHA and checks target ZIP **metadata only**. It never deserializes a model or reads CSV/ZIP payload, names, passwords, IPs or labels. Evidence report is owner-only (0600), exclusive-create. Omitting model+manifest verifies metadata only and returns PREREG_METADATA_VERIFIED_MODEL_BYTES_PENDING, not a model-freeze PASS.

Do not commit the raw dataset, packet captures, unsigned joblib/pickle or secrets. Actual inference needs trusted artifact and operator review of deserialization and model dependencies. Rotating previously exposed R2 secrets and enforcing bucket-scoped read-only access remain mandatory.

## Next gate after this PR

Check license and original file integrity, do a **bounded header/schema-only audit after preregistration**, and arrange secure data access/ground-truth review. Do not begin actual model scoring yet. Public lab research validation is not an independent operational SOC acceptance certificate.
