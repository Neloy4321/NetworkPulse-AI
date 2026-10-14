# ML Reliability & Explainability — engineering milestone (2026-10-14)

**Status:** New reliability controls, diagnostic explainability, operational guardrails,
three real capture baselines and an explicit holdout calibration study were tested.
**Not** a production-ready intrustion detector. All changes are code-only; no
real-data-trained model was promoted or automatically deployed.

## Changes implemented

1. **Reliable held-out error reports.** Native `Detector.train()` metadata
   now reports benign and attack counts, confusion matrix, FPR, one-sided
   Wilson 95% upper FPR confidence bound, alarm volume, and
   protocol/sensor/port-class slices with rates withheld for tiny benign groups.
2. **Benign calibration diagnostics.** Threshold distribution and in-sample
   benign alert counts for quantiles 0.95, 0.97 and 0.99. These estimates are
   generated from training-period *benign calibration only*; no test labels
   influence model fitting or threshold choice.
3. **Model-related explanations.** New opt-in
   `networkpulse explain-model` reports the change in Isolation Forest score
   if each *single numeric feature* is replaced by its benign-training median.
   Reports are capped to 25 canonical events and do not export source IPs,
   packet payloads or event bodies. This method is **not** SHAP, feature
   attribution, attack causality or probability calibration.
4. **Drift hardening.** Reject windows smaller than 30 events, invalid PSI
   settings and incompatible reference dimensions. Provide overall PSI
   severity and optionally labeled *retrospective* error rates. Drift alone
   cannot prove a detection failure or an attack.
5. **Safe model management.** Optional candidate gate on held-out *upper*
   FPR bound with at least 100 benign examples. Explicit `--production`
   promotion policy rejects synthetic-only models and requires an artifact
   hash match, minimum external labeled counts, declared independent-site,
   live-sensor and leakage evidence, human approval and controlled FPR.
   This local JSON receipt is **not cryptographically authenticated**, and
   a real operator must independently authenticate its issuer and data.
6. **Tests and docs.** Regression tests, updated model card/runbook, reproducible
   GitHub Actions research study. No raw source ZIP or flow rows committed.

## Predeclared real-data sensitivity study

**Pipeline**: native `Detector.train`, `Detector.score`,
`event_features`, raw UNSW-NB15 source-to-`FlowEvent` adapter.

Earlier `UNSW-NB15_1.csv` (fit and benign calibration) versus **reserved,
later** `UNSW-NB15_3.csv` (1290 after exact event deduplication,
**988 benign / 302 attacks**). No training, quantile selection or calibration
uses the held-out test labels. `seed=42`, capped uniform reservoirs (2200
training, 1300 test before dedup). 1252 benign fit and 329 benign calibration
flows in the internal training window; training attack labels do not fit
Isolation Forest.

| Predetermined benign calibration quantile | FPR | One-sided Wilson 95% FPR upper | Recall | Precision | F1 | False alerts (FP) | Missed attacks (FN) |
|---|---:|---:|---:|---:|---:|---:|---:|
| 0.97 | 10.63% | 12.35% | 86.09% | 71.23% | 77.96% | 105 | 42 |
| 0.99 | 9.21% | 10.84% | 84.44% | 73.70% | 78.70% | 91 | 47 |
| 0.995 | **8.81%** | **10.40%** | 83.77% | 74.41% | 78.82% | 87 | 49 |

This is a **trade-off**, not a production threshold recommendation:
raising the calibration quantile reduced 18 benign false alerts in this
sample relative to q=0.97, but missed 7 additional attacks. The .995
held-out observed FPR of 8.81% (95% one-sided Wilson upper approx 10.40%)
**fails a 5% operational FPR target**. These same-source cyber-range
captures do not prove independent-site generalization. Intrusions with high
cost of missed detection may justify a very different objective.

No q=.995 policy has been selected, saved to a joblib artifact or put
on the live API, and comparisons performed on these held-out labels must
not be used as optimization feedback without a *new* untouched validation
period. The original active Docker model is unchanged.

Machine-readable aggregate evidence:
[`reports/real_data/fpr_calibration_study.json`](../reports/real_data/fpr_calibration_study.json).
Successful GitHub Actions:
[research study](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/38515319879).

## Evidence versus unresolved production gates

| Reliability capability | Status |
|---|---|
| Confidence-aware labeled FPR + class counts | Implemented and tested on synthetic fixtures |
| Grouped false-positive slices | Implemented, small groups withheld |
| Conservative calibration quantile comparison | Real-data CI experiment passed |
| Real detector evaluated on offline raw UNSW capture | Measured, see [real-data report](REAL_DATA_RESULTS.md) |
| Opt-in numerical model-score sensitivity | Implemented and tested, not SHAP |
| PSI/alert budget and optional labeled audit | Implemented and tested |
| Immutable registry + artifact checksums + rollback | Existing, extended with conservative promotion guards |
| 5% production FPR acceptance | **Not passed** |
| Independent new network/site evaluation | **Not done** |
| Cryptographically verified approval/evidence | **Not implemented** |
| Real deployed Zeek/Suricata field validation | **Not done** |
| Full feature attribution/SHAP with domain-faithful perturbations | **Not implemented** |

**Do not claim Requirement #5 100% based on these code and offline tests.**
#5 is measurably stronger, but its scientific and operational gates are still
open. The testbed results are not a production score guarantee.

## Operational commands

```bash
# Local only, on trusted canonical JSONL; does not reveal IPs in the output:
networkpulse explain-model --model data/model.joblib --data data/authorized-flows.jsonl --max-events 20

# Label-aware retrospective monitoring (30+ events):
networkpulse drift-report --model data/model.joblib --data data/authorized-flows.jsonl

# Internal holdout FPR uncertainty registration (100+ benign required):
networkpulse model-registry register --name candidate-v2 --file data/trusted-candidate.joblib --min-f1 0.70 --max-alert-fraction 0.15 --max-fpr-upper-95 0.05

# Opt-in stricter production receipt policy; external attestations must be verified:
networkpulse model-registry promote --name candidate-v2 --active data/model.joblib --production --evidence data/operator-audited-validation.json
```

`explain-model` requires newly trained models with benign-feature-median
metadata. Loading old trusted artifacts for **scoring** remains compatible;
explanation intentionally fails closed for old artifacts missing baseline
metadata. No command should deserialize an untrusted external pickle/joblib.
