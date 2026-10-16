# IoT-23v2 real uploaded Zeek capture — 2026-10-16 external research audit

**Status: NUMERICAL NO-GO VERIFIED IN ORIGINAL MODEL RUNTIME; P0 operational acceptance NOT DEMONSTRATED.**

The user's authentic publicly distributed, originally labeled
`CTU-IoT-Malware-Capture-34-1` IoT-23v2 Zeek TSV file was received
and inspected independently of synthetic fixtures. The file was **not**
committed to GitHub or published as raw traffic in workflow artifacts.

## Exact source identity

- File: `2018-12-21-15-50-14-192.168.1.195-zeek-conn-log.labeled`
- Official Stratosphere distribution:
  https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-34-1/
- Bytes: **3,019,311**
- SHA-256:
  `7d1d052835439d77dae246b588d7628813bbdef21fdf3b323f4b3eb2c61ef146`
- UTC capture period: 2018-12-21 14:50:16 to 2018-12-22 14:50:13.
- 23,145 genuine TSV flow records, **all** 21 source columns present;
  1,923 labeled benign, 21,222 labeled malicious.
- Compound last Zeek column contains `label` and `detailed-label`;
  its normal tabular schema is **not JSONL**, and `-` denotes
  missing values, not numeric zero.

## Severe missingness / selection-bias evidence

We require all frozen model numeric features to be present; `-` is
**never silently set to zero**. Thus:

| Label / malicious category | Full original | Complete-case scored | Fraction |
| --- | ---: | ---: | ---: |
| Benign | 1,923 | 1,003 | 52.16% |
| C&C | 6,706 | 4,294 | 64.03% |
| DDoS | 14,394 | 13 | 0.09% |
| Horizontal Port Scan | 122 | 11 | 9.02% |
| **Total** | **23,145** | **5,321** | **22.99%** |

**17,824 / 23,145 (77.01%)** rows lack Zeek duration and/or original/
response payload byte counters. In this capture their missingness is
highly class/type-dependent. Accordingly, even an ideal numerical result
on these 5,321 flows cannot be generalized to the full 23,145 without
an audited missing-data inference contract.

## Preliminary frozen-model local research score — NOT exact-runtime certified

Retrieved the previously trained/immutable source-only RF GitHub
Actions artifact **12043926108** from run
https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/38894227857,
and its manifest artifact **12042939629**. The frozen model's exact
SHA-256 matches the source-only freeze:

`ba5fbc2cb171b0f79a31d99e71fbe438135325babc9d939d26c8589f66ff954b`

Original training dependency: **scikit-learn 1.9.1**. Local
exploratory scoring used **scikit-learn 1.8.0**, which generated
`InconsistentVersionWarning` on deserialization. Feature extraction
reproduced the source-side `rf_supervised_port_buckets_no_state`
numeric behavior and fixed cutoff **0.5**. We did **not** fit, tune,
calibrate or alter the model based on IoT-23 labels.

| Complete-case confusion matrix | Predicted benign | Predicted anomaly |
| --- | ---: | ---: |
| Actual benign | TN 856 | FP 147 |
| Actual attack | FN 4,316 | TP 2 |

- Observed benign FPR **14.6560%**; Wilson 95% upper **16.9796%**:
  **numerical FAIL** (maximum 5%).
- Observed attack recall **0.0463%**; Wilson 95% lower **0.0127%**:
  **numerical FAIL** (minimum 80%).
- Scope: a **laboratory-family controlled IoT scenario**,
  **complete-case subset only**, already exposed to research analysts,
  not an independently operated production SOC/site.
- True row-level UNSW train/IoT test overlap was **not locally verified**:
  source ledger wasn't available in the local environment at this point.
- This is provisional; exact 1.9.1-runtime confirmation is being
  automatically attempted in a separate [GitHub research CI workflow]
  (https://github.com/Neloy4321/NetworkPulse-AI/actions).
  Only verified evidence may be described as exact-runtime confirmation.

## A critical deployed-adapter mismatch

The existing production `networkpulse.adapters.from_zeek()` normalizes
native missing `duration`, `orig_bytes` and `resp_bytes` into
zero, whereas the strict target-data research converter **drops such
rows** instead of inventing measured zeros. This means the operational
feature semantics and audited complete-case research result differ.
**Do not declare detection/release acceptance until an explicitly
versioned sensor-missingness contract is designed, validated and
deployed identically at training and inference.**

The observed local recall collapse and FPR are not permission to
retrain or move the threshold using this previously exposed target.
If a new source-development strategy is needed, record it using
already-exposed UNSW/TON/IoT-23 as development and reserve an untouched
genuinely new dataset for final prospective testing.

## Decision and follow-ups

**P0 Operational ML Acceptance: NO-GO.** Source-only successful research
and a signed active deployed model with independent field reviewer
evidence remain distinct acceptance criteria. An official public IoT
laboratory capture is valuable for external-family research, but alone
cannot supply original independently operated production evidence.
Research evaluations must be reported with entire-capture missingness,
capture/day correlation and observed failure modes; never replace
malicious labels, fabricate network counters or cherry-pick only good
source results.


## VERIFIED exact-version freeze/target recheck: 2026-10-16

The public IoT-23v2 original was independently fetched inside the GitHub
Actions source-only research runner and its bytes/size verified against
the **exact user-uploaded SHA-256 before reading flow content**. The previously
frozen source-trained RF was rebuilt from the identical approved UNSW archive.
Model SHA remained
`ba5fbc2cb171b0f79a31d99e71fbe438135325babc9d939d26c8589f66ff954b`,
the restricted 23,551-row source identity ledger was regenerated and its SHA
checked, and **zero canonical/fingerprint training-test overlaps** were found.

**Full authentic execution**
[GitHub Actions run 38901875043](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/38901875043)
**SUCCEEDED with 85 focused tests + Ruff**. Aggregate-only evidence artifact:
**12046232907**, file `iot23v2-exposed-recheck.json`.

Model was scored in the **exact original model training runtime**
(Python 3.12.15, scikit-learn 1.9.1). It confirmed the preliminary local
confusion matrix **exactly**:

| Actual \ Predicted | Benign | Anomaly |
| --- | ---: | ---: |
| Benign | TN **856** | FP **147** |
| Malicious | FN **4,316** | TP **2** |

- Benign **observed FPR = 14.6560%**; 95% Wilson CI **12.6022%–16.9796%**;
  max permitted 95% upper **5%**: **FAIL**.
- Attack **observed recall = 0.0463%**; 95% Wilson CI
  **0.0127%–0.1687%**; required 95% lower **80%**: **FAIL**.
- **77.01%** of original flow rows cannot be scored using the required
  unmodified sensor feature contract. The remaining 5,321 rows may not be
  representative: this result only describes the complete-case population.
- Original source attack labels have not been independently re-adjudicated;
  same operator/site provenance and signing/deployment remain unverified.
- IoT-23v2 is now exposed development/research evidence, **not** a pristine
  prospective holdout for a future model candidate.

**Interpretation:** With unmodified source-only frozen RF weights and
cutoff 0.5, **the cross-dataset laboratory test really fails**. A green
GitHub job proves faithful measurement and integrity—not network ML
acceptance. No score-driven tuning, post-hoc threshold optimization or
retroactive pass criterion is allowed. An engineered, versioned
missing-value-aware production feature contract and a new source-side
training/generalization strategy are necessary BEFORE reserving another
unseen site/dataset for independent acceptance. Moreover, operational
production signoff requires an actual signed active compatible model,
site/day/analyst review, latency/alert workload and lawful operator evidence.

The older **preliminary local-runtime** section remains above as historical
context only; this section supersedes its dependency-warning limitation.
