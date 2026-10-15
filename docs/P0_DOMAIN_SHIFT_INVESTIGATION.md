# P0 Operational ML acceptance — domain-shift investigation protocol

**Engineering phase:** diagnostic instrumentation, not model-quality remediation or production sign-off.
**Evidence context:** native UNSW-NB15 earlier source capture -> TON `Network_dataset_23.csv`, previously tested.
**Known observed native result:** 105 FP of 480 benign = 21.875% FPR (95% Wilson upper 25.7886%);
4,507 TP of 4,520 attacks = 99.7124% recall. The acceptance gate **FAILED**.

## Why this milestone is useful

The deployed feature mapping is not a dataset-specific benchmark: native
`networkpulse.features.event_features` consumes connection state, protocol,
log durations, byte/packet volumes, byte rate, response fraction and port data.
UNSW and TON may record flow states, duration and counters differently.
Unseen categorical vocabulary after training is mapped by the fitted
`DictVectorizer`; an anomalous score may change in the target network even
for legitimate benign flows. This is a **hypothesis**, not a proven cause.

The source-only calibrated q=.995 threshold and even a high attack recall
are not sufficient to guarantee benign cross-domain FPR, let alone a field
network with different normal service mix.

## New read-only post-hoc diagnostics

The frozen research-only model remains unchanged: same authentic ZIP checksums,
same 2,200 source sample, same q=.995, same 5,000-row TON reservoir,
same primary confusion-matrix and quality gate. The new report includes:

1. **Benign numeric feature shifts**: source/target p25/median/p75 for the
   exact 10 numeric features used by the current native detector, with
   signed median difference measured relative to source benign IQR.
2. **Protocol/state false-alert slices**: confusion-matrix counts and 95%
   Wilson intervals. FPR is shown only for groups with >=30 benign flows;
   recall only for groups with >=30 attacks. Small groups are suppressed.
3. No original IP addresses, ports in event rows, identifiers, raw traffic,
   per-host counts or source-row exemplars are uploaded. This artifact
   contains only aggregates; it is not privacy or site-independence proof.

Crucially **TON _23 was already exposed**, including labels and previous
performance. The diagnostic MUST NEVER be used to pick a new model,
feature subset, threshold, quantile or trained artifact while reusing TON _23
as if untouched independent evaluation.

## Next source-only model-improvement experiments (NOT performed by this milestone)

Freeze an explicit *development-only* protocol before modeling:

- Use **UNSW source data** and designated source calibration/development
  splits only; keep already-inspected UNSW _3/_4 as *previously exposed*,
  never claim they are new, pristine holdouts.
- Compare carefully versioned native candidate feature contracts: categorical
  state normalization, protocol-capped benign quantiles, robust numeric
  transforms and minimal sensor-semantics-compatible subsets.
- No labels from the previously exposed TON _23 can influence these
  candidate decisions or supervised training; no test-domain score-driven
  threshold adjustment.
- Choose a candidate using source-only temporal/grouped development splits,
  document objective, data fingerprints, slices and algorithm parameters,
  serialize SHA-pinned frozen model, record environment/package lock and
  complete training ID ledger.
- Evaluate **once** on a different newly authorized untouched, authentic,
  labeled and independently operated site/capture, preserving label adjudication
  and grouping information.

## Acceptance prerequisites

- Predeclare the **same** observed-quality conditions: FPR 95% upper <=5%
  and attack recall 95% lower >=80%; report both numerators/denominators.
- Adequate benign support, source identity/time leakage barriers,
  uncertainty grouped by site/day/host, per-hour real alert burden.
- Approved signed active model and operator-authorized live/staging evidence.
- A CI or script that finishes successfully is **not** proof the numerical
  quality gate passed.

**State:** P0 operational ML acceptance **NOT DEMONSTRATED**.


## Executed authentic run: GitHub Actions 38783500339

Research-only native job **completed successfully** on original SHA-pinned
UNSW and TON ZIPs after its tests passed. [Run](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/38783500339),
artifact `11995769965`, `native-unsw-to-ton.json`, extracted report
SHA-256 `930dbe8c94bfeebd454c2d91a7a83681d0c69e48dba931b915e0e50a9e32054f`.

**The original metrics remain unchanged and acceptance still FAILS:**
TN 375, FP 105, FN 13, TP 4,507; observed FPR 21.875%,
recall 99.7124%. The research job's successful execution is not a PASS.

### Post-hoc false-alert slices (already-exposed TON labels)

| Connection state | Benign | FP | Observed FPR | 95% Wilson FPR |
|---|---:|---:|---:|---:|
| `s0` | 104 | 70 | 67.3077% | 57.8163%–75.5660% |
| `sh` | 90 | 22 | 24.4444% | 16.7328%–34.2484% |
| `sf` | 258 | 3 | 1.1628% | 0.3962%–3.3623% |

Other low-support state groups are suppressed, so these rows need not sum
to all 480 benign and 105 FP. The `s0` slice explains *where* 70/105
false alerts occur in this previously inspected capture; it does **not**
demonstrate why the model generated them. No source/target state vocabulary
harmonization has been independently validated; no state-specific thresholds
were selected.

| Protocol | Benign | FP | Observed FPR |
|---|---:|---:|---:|
| `tcp` | 225 | 33 | 14.6667% |
| `udp` | 253 | 70 | 27.6680% |

The benign numeric median comparison provides additional domain-shift
hypotheses, not statistical significance or acceptance evidence:

| Native numeric feature | Source benign median | TON benign median | Delta / source IQR |
|---|---:|---:|---:|
| `log_orig_bytes` | 7.677400 | 5.257495 | -1.2213 |
| `log_resp_bytes` | 8.227643 | 4.713210 | -0.8046 |
| `log_resp_pkts` | 2.944439 | 1.098612 | -0.7948 |
| `log_bytes_per_second` | 11.338584 | 9.218484 | -0.6652 |
| `log_orig_pkts` | 3.135494 | 1.791759 | -0.5692 |

These rows use the authentic labels to *describe* the previously seen test
distribution. **They must not be fed into training/calibration or used to
choose a winning candidate claimed as independent on TON _23.** Group
confidence bounds are flow-level, not cluster/site-robust.

### Source-only next implementation decision

Before any new candidate or FPR claim, pre-register sensor-state mapping
semantics and duration/byte/packet units based on **data documentation and
source-only fit/development observations**, independently of TON _23 label
performance. Freeze an explicit versioned feature contract, candidate
selection ledger and model SHA; only a newly acquired untouched authentic
external network capture can establish out-of-sample acceptance.
