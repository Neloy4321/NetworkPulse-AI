# P0 Stage 1 — source-only native feature contract and reproducible baseline

**Status:** engineering and repeatable authentic-source benchmark foundation only.
**Not a claim of Operational ML Acceptance.** No production model is modified.

## Scope and provenance

- Input: *only* authenticated private Cloudflare R2 archive `OneDrive_2_9-14-2026.zip`, exact length **586,382,286 bytes**, SHA-256 **`3c7500f120405b21b44a2bf05134f49491f88a655ae3091fc1b269c4c9ece79a`**.
- Record member: **`UNSW-NB15_1.csv`** selected through the existing safe archive member resolver and parsed by `live_unsw.read_reservoir`. Entire member is scanned for input validation; deterministic uniform reservoir size **60,000**, seed **42**.
- Never load TON, CIC, the exposed `Network_dataset_23.csv`, a production signed model, or unapproved dataset bytes for Stage 1.
- Repo research feature contract version remains **1**, **no production-side feature changes**. The first baseline is exactly the existing native `IsolationForest` and `event_features`.
- Source-only sample de-duplicates canonical event keys and adapter-invariant flow fingerprints before two **distinct** development protocols (no model selection):
  1. **Strict chronological 75/25** boundary: all equal timestamps on one side. The initial authentic 12,000-row audit run had **2,986 benign and 0 attacks** in this late-time development segment; no two-class FPR/recall was possible. A larger source-only sample does **not** automatically resolve a class-segregated timeline. The actual blocked status is preserved, not silently replaced by a result.
  2. **Host-pair/protocol-group-disjoint 75/25** split: seed=42, distinct `(src_ip,dst_ip,proto)` grouping, assignment independent of labels, no shared group across source-fit/dev. It permits time overlap and is **same-source development only**, not temporal generalization or cross-site proof. In the initial 12,000-row sample this held out **35 attacks and 2,973 benign**, insufficient for the prespecified ≥100/class requirement. To improve the precision of rare-class sampling, the fixed reservoir was enlarged transparently to **60,000**, without using TON labels or adjusting based on model performance. Further CI outcomes must be reported, not assumed.
- Both protocols keep the existing `train()` benign internal fit/calibration and fixed IsolationForest feature v1, seed=42 and calibration quantile=.995. When valid development labels exist, only aggregate descriptive FPR/recall metrics are reported, **never** operational acceptance.
- Source ZIP size/SHA, group identity, chronology, minimum two-class support (100 benign and 100 attacks), and failure/blocked reasons are explicit gates. Training and evaluation are never tuned on TON or an external holdout.

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

Evidence fields: source SHA, selected row counts, excluded duplicates, strict
chronological separation flag and blocked class-support counts, group-disjoint
fit and development population, native model feature version, calibration
metadata, confusion matrix, FPR and recall intervals when genuinely available,
sanitized feature summaries, Python/NumPy/scikit-learn versions, and a stable
SHA-256 of *protocol settings*. A timestamp stored in model
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


## Executed Stage 1 real-source CI evidence (2026-10-16)

[Authentic GitHub Actions run 38879398171](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/38879398171):
**PASS** for the source-only audit job with 23 focused tests passed, private
UNSW R2 exact-byte/SHA-256 verification, a 60,000-flow source-only audit, and
an aggregate-only artifact **12036717883**. This confirms execution only.

- Full original member scan: **699,934 valid / 67 invalid** records;
  **677,719 benign / 22,215 anomaly** labels. Only 60,000 uniformly
  reservoir-sampled flow events proceed to the development investigation.
- Chronological split after duplicate removal: **44,031 source-fit** /
  **14,679 development** events, with strict timestamp separation; development
  labels **14,679 benign / 0 anomaly**, hence two-class metrics **NOT available**.
- Fixed-seed host-pair/protocol-disjoint split: **45,717 source-fit** /
  **12,993 development**, with **420 original groups** and no group overlap;
  development labels **12,729 benign / 264 anomaly**. No chronological
  independence is claimed.
- Frozen-code (not production-frozen-artifact) native IsolationForest feature v1
  research baseline: **TN 12,567 / FP 162 / FN 245 / TP 19**;
  source-only observed benign **FPR 1.2727%** (95% Wilson
  **1.0921%–1.4826%**), attack **recall 7.1970%** (95% Wilson
  **4.6555%–10.9662%**).
- This development sample reports observations from **one capture date
  (2015-01-22)**. Same-capture and correlated-flow limitations are fundamental.
  A small FPR here does not offset catastrophic missed attacks and does not
  imply an external-site acceptance improvement.
- Research protocol SHA-256: 
  `a19dcef2f44fdafe2064f227309f870f113b31ed9e3b5df1341ba2978c00d9b1`.
  Numeric acceptance is **NOT demonstrated**, the previously exposed TON
  benchmark remains **FAILED**, and no feature/model/threshold is promoted.

**Stage 2 design consequence:** the source-only development diagnostics need
both low FPR and adequate attack recall. Confirm attack label interpretation and
benign-fit calibration semantics from UNSW source documentation, then
pre-register *few* alternative versioned candidate representations without
using exposed TON outcomes for selection. A new untouched external labeled
capture is still necessary to make a credible independent acceptance claim.
