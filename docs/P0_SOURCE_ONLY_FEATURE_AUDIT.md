# P0 Stage 1 — source-only native feature contract and reproducible baseline

**Status:** engineering and repeatable authentic-source benchmark foundation only.
**Not a claim of Operational ML Acceptance.** No production model is modified.

## Scope and provenance

- Input: *only* authenticated private Cloudflare R2 archive `OneDrive_2_9-14-2026.zip`, exact length **586,382,286 bytes**, SHA-256 **`3c7500f120405b21b44a2bf05134f49491f88a655ae3091fc1b269c4c9ece79a`**.
- Record member: **`UNSW-NB15_1.csv`** selected through the existing safe archive member resolver and parsed by `live_unsw.read_reservoir`. Entire member is scanned for input validation; deterministic uniform reservoir size **12,000**, seed **42**.
- Never load TON, CIC, the exposed `Network_dataset_23.csv`, a production signed model, or unapproved dataset bytes for Stage 1.
- Repo research feature contract version remains **1**, **no production-side feature changes**. The first baseline is exactly the existing native `IsolationForest` and `event_features`.
- Source-only sample de-duplicates canonical event keys and adapter-invariant flow fingerprints before a **strict chronological 75%/25% fit/development boundary**. Rows sharing the boundary timestamp remain on one side. Internal benign fit/calibration of the source-fit portion is existing `train()`; model seed=42, benign calibration quantile=.995.
- Dev predictions are reported with confusion counts and Wilson intervals as **descriptive source-only performance**, not external or P0 acceptance. Invalid or insufficient classes/chronology/source checksum fail closed.

## Initial feature audit questions

The contract has authentic original raw-column mappings in `live_unsw.raw_unsw_to_event`:

| Canonical field | UNSW source | Contract question |
|---|---|---|
| timestamp | `stime` | UNIX seconds and sensor capture clock; preserve timezone and time ordering |
| duration | `dur` | Verify sensor duration units and aggregation/window truncation |
| orig/resp bytes | `sbytes`, `dbytes` | Understand byte counter direction and interpretation |
| orig/resp packets | `spkts`, `dpkts` | Validate direction and counter semantics |
| src/dst ports | `sport`, `dsport` | Native `dst_port` treated numerically; ordinal relationship is not a documented risk relationship |
| proto | `proto` | Capped `tcp/udp/icmp/other`, no invented protocols |
| connection state | `state` | Sensor-specific vocabulary, do not equate with TON `conn_state` merely from matching strings |
| ground truth | `label` | Dev evaluation only; fit/calibration remain benign-only |

Existing `event_features` uses log duration, bytes, packets, bytes/sec,
bytes/packet, response fraction, raw destination port, privileged-port flag,
one-hot protocol and one-hot connection state. A numeric destination-port value,
sensor-specific categorical state vocabulary, zero-duration time divisor cap
`max(0.01, duration)`, and source counter discrepancies are **hypotheses**
for later source-only ablations, **not proven causes of the known TON false positives**.

The generated report counts zero-duration flows, no-response-packet flows,
high destination ports, zero-byte flows, protocol vocabulary, top sanitized
connection states, and quantiles/min/max for numeric model features. It contains
**aggregate-only** data and never serializes source IPs, destination IPs,
host identifiers, row text, raw network ZIPs or generated flow samples.

## Run and evidence

```bash
python -m networkpulse.evaluation.source_only_feature_audit \
  --unsw-zip unsw-source.zip \
  --output real-evidence/source-only-feature-audit.json
```

CI `.github/workflows/source-only-feature-audit.yml` separately fetches only
the approved UNSW source object through authenticated read-only S3 GetObject,
checks exact bytes and SHA-256 *before* exposing the local ZIP to the audit,
runs regression tests, preserves only the aggregate JSON report, and removes
the ZIP at the end. GitHub Actions secrets are needed; forked/untrusted PRs
cannot access them. Missing/failed evidence makes the job **red**, never green.

Evidence fields: source SHA, selected row counts, excluded duplicates, exact
chronological separation flag, fit and development population, native model
feature version, calibration metadata, confusion matrix, FPR and recall
intervals, sanitized feature summaries, Python/NumPy/scikit-learn versions
and a stable SHA-256 of *protocol settings*. A timestamp stored in model
metadata means binary model artifact hashes should **not** be assumed identical
across runs; no production promotion takes place.

## Predeclared research guardrails and future Stage 2

1. Review source-only feature/sensor semantics and document actual allowed
   state vocabulary, packet/byte units, and timestamp coverage **without
   inspecting or optimizing for exposed TON results**.
2. Decide a small number of versioned candidate feature contracts *in advance*,
   e.g. categorical port buckets, source-documented state normalization,
   robust byte-rate handling. No arbitrary outcome-driven hyperparameter sweeps.
3. Use source-grouped/temporal development splits to select candidate,
   freeze configuration, sample IDs, dependencies, signed model SHA and model
   provenance. Beware correlated flows and split-day coverage.
4. Acquire a **new truly untouched** independently operated external capture
   with authentic adjudicated benign/attack labels. Previously inspected TON
   `Network_dataset_23.csv` is NOT pristine and cannot be reused to claim
   independent model validation.
5. External numeric gate: 95% Wilson **upper benign FPR ≤5%** and 95% Wilson
   **lower attack recall ≥80%**, plus day/site-group support, real alert burden,
   deployment and active signed-model evidence. An internal source benchmark
   is neither site-level validation nor operational certification.

**Known prior TON result:** 105 FP / 480 benign (21.875% observed FPR,
25.7886% Wilson upper); 4507 TP / 4520 attacks. This remains **FAILED**.
Stage 1 does not change or improve this measured result.
