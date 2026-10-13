# Real external network intrusion benchmarks — October 2026

> **Reproducible real-data baselines, NOT production detection accuracy.** Actual
> user-supplied external network traces were inspected and four offline models
> compared. An unseen cyber-range capture/date is distinct from an independent
> network or an operational field deployment. No evidence here verifies the
> deployed `model.joblib` on real flow sensors.

**Passed GitHub Actions run:** https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/38461006624

**Workflow:** `.github/workflows/real-dataset-benchmarks.yml`  
**Source:** `tools/real_data_benchmark.py` (all three formats, no raw rows committed)  
**Full machine-readable public-safe results:** `reports/real_data/verified_baselines.json`

## What was actually tested

- All three Drive ZIPs downloaded, exact archive sizes checked, SHA-256 checksums
  preserved in reports. Raw ZIP files are removed from ephemeral CI runners.
- Two original capture files per dataset were **fully scanned for valid/invalid
  row counts and binary label distribution**; bounded **uniform reservoir
  samples** used for fitting/testing (`seed=42`, max 2,200 train / 1,300 test).
  Remaining capture files were not exhaustively benchmarked.
- Fit/calibration rows do not use held-out attack labels. Isolation Forest and
  LOF novelty are **benign-only fitted**, with a separate benign calibration
  split. A fixed-rule baseline uses benign-only calibration thresholds.
- A **separate supervised Random Forest reference** uses earlier training-file
  attack labels; never held-out test labels. For TON-IoT-like data, sufficient
  chronological benign calibration was unavailable for this reference, so no RF
  result was reported.
- No raw IP address, UID, HTTP text, source identity, event timestamp or target
  label is included as a model input. Numeric flow durations are normalized
  (CIC microseconds → seconds). Dataset-specific feature names are harmonized
  explicitly. Do not assume original 46/49/79 raw features are equivalent.
- Train/test capture files are separate, fingerprint-based duplicate filtering
  is applied to **sampled** records (not every full raw row), and test results
  are independently held out.
- TON-IoT-like and raw UNSW contain numeric timestamps; sampled train/test
  periods passed chronological no-overlap checks. CIC's Wednesday → Friday
  split follows the published capture day filenames, not verified row clocks.

## Experimental results

| Dataset | After-dedup test flows | Attacks in test | Isolation Forest F1 | LOF F1 | RF F1 |
|---|---:|---:|---:|---:|---:|
| toniot | 593 | 456 | 0.41% | 0% | N/A |
| unsw_raw | 785 | 66 | 51.06% | 50% | 66.67% |
| cic2017 | 1295 | 763 | 0% | 0.51% | 99.41% |

F1 must be read with FPR, alert fraction, confusion matrix, precision/recall,
ROC-AUC and PR-AUC in the JSON report. Some results are *very poor*:

**CIC-IDS2017:** trained on Wednesday's DoS/benign capture and tested on
Friday's DDoS/benign capture. Random Forest achieved high apparent F1
(99.41%),
but Isolation Forest did not detect the selected DDoS flows at all, with
31.39%
FPR. The supervised result can reflect attack/testbed artifacts despite
excluding IPs: it **must not** be called broad real-world DDoS accuracy.

**UNSW-NB15 raw:** `UNSW-NB15_1.csv` (early) versus `UNSW-NB15_4.csv`
(later), with a 49-column raw headerless parser. Isolation Forest F1
51.06%;
Random Forest F1 66.67%.
The test covers multiple labeled attack families and has 66 attacks in the
sample after duplicate filtering. Small per-family samples must not be
generalized to all attacks.

**TON-IoT-compatible:** `Network_dataset_1.csv` versus
`Network_dataset_23.csv` with 46/47-column Zeek-like schema and time
separation, primarily scanning in training versus backdoor/mitm in test.
This **unseen-attack shift** is hard: IF F1
0.41%,
LOF F1 0%.
The post-dedup train sample contains only 132 benign flows, 99 used for fit
and 33 for chronological calibration; this is *not* enough to claim a robust
production model or a representative alert rate.

## Remaining gates before calling requirement #1 100% complete

1. Independently controlled **unseen network/site** capture and a verified
   external acquisition/provenance chain; the ZIP with generic
   `Network_dataset_*.csv` names only has a TON-IoT schema match.
2. Larger, repeated time- and attack-family-held-out **sensitivity analyses**;
   uncertainty intervals, imbalanced sampling/duplicate-reweighting checks and
   true per-class denominators across more days.
3. Real sensor Zeek/Suricata end-to-end verification of the **deployed**
   NetworkPulse scoring model, calibrated to a measured false-positive budget
   on benign traffic, followed by independent regression tests.

**Assessment:** Source ingestion, original-data labels, leakage-guarded
offline benchmarks, comparisons and reproducible GitHub evidence are now
implemented and passed. Requirement #1 is **materially progressed but not
100% scientifically or operationally validated**.

### Source integrity and privacy

- Dataset 1 ZIP SHA-256: `411ec9768cc06586265095292f3fdc78f10306d26c9e4e227079f7c286520ad0`
- Dataset 2 ZIP SHA-256: `3c7500f120405b21b44a2bf05134f49491f88a655ae3091fc1b269c4c9ece79a`
- Dataset 3 ZIP SHA-256: `c3f26274b36c837ccf28ffd2dbf4582941c30b3ee70a635c6e5b2f87c4727928`

Raw traffic never gets committed; reports contain aggregates and source
file names only, without individual packet payloads, IPs or identities.

## Native NetworkPulse Detector evaluation — real UNSW capture

**Tested actual `networkpulse.detector.train`, `Detector.score` and
`networkpulse.features.event_features`, not just separate scikit-learn baselines.**
Original headerless raw UNSW-NB15 flow records were validated into the canonical
`FlowEvent` schema. Source `UNSW-NB15_1.csv` is earlier than held-out
`UNSW-NB15_4.csv`. Real-trained and synthetic-trained in-memory models were
evaluated on the **same 1,288 exact-event-deduplicated real flows (257 attacks)**.

| Native Detector variant | Precision | Recall | F1 | Benign false-positive rate |
|---|---:|---:|---:|---:|
| Real early-capture training + benign calibration | 63.38% | 87.55% | **73.53%** | **12.61%** |
| Existing synthetic-demo *training regime* (fresh model) | 25.37% | 92.61% | **39.83%** | **67.90%** |

The synthetic reference is **newly fitted using the same seeded generator**,
not a checksum-matched copy of any model currently running on the user's PC.
Neither experimental model was deployed or promoted. Both are the **native
NetworkPulse scoring architecture**, not the prior scaled/engineered
dataset-specific baseline. The 12.61% real-trained benign alert rate would
still be potentially unacceptable for a production SOC. There is no verified
independent-site holdout, so do **not** infer field accuracy from these numbers.

The detailed provenance, run counts, thresholds, confusion matrices, ROC/PR-AUC
and explicit constraints are in
[`reports/real_data/native_unsw_detector.json`](../reports/real_data/native_unsw_detector.json).
CI evidence: https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/38462247199

**Requirement #1:** Real dataset acquisition, robust adapters, source-line
counting, source hashing, explicit cross-capture benchmarking, multi-model
comparison, a verified native pipeline score and CI are complete as
**engineering milestones**. An external independent network/site,
real deployed sensor model check and acceptable alert budget remain missing.
Therefore #1 is **not honestly 100% complete**.
