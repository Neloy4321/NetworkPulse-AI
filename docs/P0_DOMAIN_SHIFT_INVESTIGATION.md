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
