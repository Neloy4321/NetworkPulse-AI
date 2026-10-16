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


## Pre-registered Stage 2 supervised research candidates — before authentic execution

**Change in learning regime:** The existing native IsolationForest remains untouched
and is still the shipped *unsupervised* detector. Because Stage 1 source-only
host-pair-disjoint development recall was 19/264 = 7.197%, Stage 2
investigates two **supervised alternatives** using genuine source-fit labels.
These are research-only estimators, **not drop-in Detector replacements**.

Candidate names and fixed source-only protocol:

- `rf_supervised_v1`: sklearn `RandomForestClassifier` with current
  `event_features` v1 and `DictVectorizer` fitted on source FIT only.
- `rf_supervised_port_buckets_no_state`: same estimator, but keep existing
  numeric behavioral features and protocol indicators; drop numeric `dst_port`,
  `dst_is_well_known` and all sensor-specific `state=...` features. Use
  one-hot port class `well_known` (0..1023), `registered` (1024..49151),
  `dynamic` (49152..65535). No invented state translation.

Both candidates: `n_estimators=160`, `max_depth=12`,
`min_samples_leaf=10`, `class_weight="balanced_subsample"`,
`random_state=42`, `n_jobs=1`. Classify at fixed probability **0.5**;
do not optimize thresholds on development labels. Report all candidates,
confusion matrices, FPR, recall, Wilson intervals, class support, source hash
and protocol digest. **Do not automatically select a winner or promote a model.**

Use the exact pinned UNSW archive and `UNSW-NB15_1.csv`, full CSV scan,
seeded **60,000** row reservoir (seed 42), de-duplicated existing
host-pair/protocol-group-disjoint 75/25 FIT/DEV split. At least **100 genuine
benign and 100 attack** flows must exist in EACH partition. Host-pair group
and canonical/fingerprint overlap checks fail closed. Train labels come only
from FIT. No TON, CIC, field holdout or DEV labels are used to fit, build a
vectorizer, select hyperparameters or calibrate probability threshold.

This is *same-source development* with possible temporal overlap, **not**
independent-site validation or proof of improved production FPR. Any future
candidate freeze must separately document grouped/temporal support, training
ledger, reproducibility, production contract integration, and a genuinely
untouched independently operated and labeled external capture. Old exposed
TON test results cannot steer model selection.


## Executed Stage 2 source-only supervised experiment (2026-10-16)

**Authentic GitHub Actions evidence:** [Run 38883010531](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/38883010531),
artifact **12038905079** (aggregate files `source-only-feature-audit.json`
and `source-only-candidates.json`; no raw traffic or model artifacts uploaded).
Ruff checks passed and **33 focused tests passed**. Private R2 pinned UNSW
source bytes were verified before either research run.

The fixed source-only split has **45,717 FIT** records (44,373 benign,
1,344 attack) and **12,993 DEV** records (12,729 benign, 264 attack)
across **420 host-pair/protocol groups**. Same capture and possibly
overlapping times: **not an independent site, not a temporal holdout**.

| Predeclared candidate | TN | FP | FN | TP | Observed FPR | 95% FPR upper | Recall | 95% recall lower |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Existing unsupervised IsolationForest v1 (Stage 1 reference) | 12,567 | 162 | 245 | 19 | 1.2727% | 1.4826% | 7.1970% | 4.6555% |
| Supervised RF using current v1 features | 12,146 | 583 | 11 | 253 | 4.5801% | 4.9572% | 95.8333% | 92.6942% |
| Supervised RF with port buckets and no sensor state | 12,105 | 624 | 13 | 251 | 4.9022% | 5.2911% | 95.0758% | 91.7586% |

The *source-only* v1 RF candidate crosses the **numerical** FPR/recall
confidence-bound criteria on this **development dataset only**. The
sensor-state-ablated RF **does not** meet the source-only 5% FPR upper bound.
This is neither prospective statistical generalization nor permission to
claim an operational ML acceptance PASS. In particular, supervised v1 RF
raises observed false alarms from 162 to **583 among 12,729 benign** compared
with the original low-recall IF baseline. This source-side tradeoff
requires analysis before any deployment.

**Reproducibility:** Stage 2 protocol SHA-256
`503a18093068bee388185d3b1efd4a8346cc10df4bafa571cc6148b4599d8faa`,
UNSW source ZIP SHA-256
`3c7500f120405b21b44a2bf05134f49491f88a655ae3091fc1b269c4c9ece79a`.
The fixed research candidates, source-only grouped fit/dev partition and
threshold=0.5 are specified in code; no model is saved as a deployable or
signed artifact, no winner is automatically selected, and TON was not
used in development.

**Next gate before any model freeze:** establish documented event/counter
semantics and source-only multi-capture/day or independently operated
group validation, stress-test class prevalence and false-alert burden,
and decide a *single* candidate only under a preregistered and reproducible
source-development selection protocol. Then freeze its artifact and training
ledger **before** acquiring/scoring a genuinely untouched external dataset.
The previous exposed TON `Network_dataset_23.csv` cannot validate a new
candidate as untouched. Signed active-model equivalence, deployment
reliability and operator-reviewed production false-alert burden are still
unproven. P0 Operational ML Acceptance remains **NOT DEMONSTRATED**.


## Stage 3 — locked same-UNSW cross-capture stress protocol

Before making any production promotion decision, evaluate the *exact same
predeclared* two supervised research candidates on captures 2, 3 and 4 from
the **same pinned UNSW archive**. This is not a new site or independent family.

- Source FIT: fixed seed 42, 60,000-row reservoir from `UNSW-NB15_1.csv`,
  canonical/fingerprint-deduplicated host-pair/protocol-group split. Use FIT
  labels only for supervised RandomForest fitting. Source development rows
  are not used to fit or tune the fixed cutoff.
- Stress captures: `UNSW-NB15_2.csv`, `UNSW-NB15_3.csv`,
  `UNSW-NB15_4.csv` with separate uniform reservoirs **8,000 rows** each,
  seeds **43, 44, 45**, each member fully scanned and validated. Exact
  row/source-fit normalized fingerprint overlap is excluded; count exclusions.
  This protection covers **sampled rows only**, not all records in a capture.
- Model parameters and threshold are the fixed Stage 2 values; evaluate BOTH
  candidates with no target-label-informed selection or reranking.
  At least **100 benign and 100 attack** distinct flows per capture is required
  to report binary FPR/recall. Otherwise mark the capture **blocked** instead
  of generating an invented recall.
- For each supported capture, report aggregate TN/FP/FN/TP, observed FPR,
  recall, Wilson intervals and diagnostic numerical target flags
  (**FPR upper <=5%; recall lower >=80%**). A metric target flag is
  **NOT** operational or untouched holdout acceptance. Capture 4 was
  previously inspected in an older UNSW experiment.
- Report details only in an aggregate GitHub Actions artifact, never raw
  flow addresses, identifier keys, signed production model artifacts, or
  source ZIP. The original IsolationForest production model remains unchanged.

**Interpretation:** This is within-UNSW multi-capture stress, susceptible to
shared simulation topology, sensor specifics, training-sample coverage and
flow correlation. The same-source chronological split previously had no
attack examples in its development portion. Any stress failure is a
real research finding, not grounds for weakening the 5%/80% external
predeclared acceptance thresholds. A new untouched independently operated
labeled site plus real deployment equivalence remains essential for P0.


## Original dataset source and intended-use boundary

Official UNSW Canberra project page:
https://research.unsw.edu.au/projects/unsw-nb15-dataset

UNSW says its raw traffic was generated in a controlled cyber range with
IXIA PerfectStorm, with both normal traffic and **synthetic attack** traffic.
Argus/Bro-derived network flow attributes and labels are recorded in four raw
CSV parts (approximately 2.54 million rows combined); this is **not** an
independently operated production SOC capture. The project's official page
permits **academic research use** and calls for author agreement for commercial
use. Its original usage/citation terms must be reviewed before redistributing
data or commercializing a training/deployment system.

Specific source-side feature semantics from the project's descriptions:
- `dur`: total duration of the record.
- `sbytes`/`dbytes`: source-to-destination/destination-to-source bytes.
- `spkts`/`dpkts`: direction-specific packet counts.
- `state`: original dataset's protocol-dependent state; not a documented
  universal Zeek connection state mapping.
- `Stime`: start timestamp; native adapter reads it as UNIX seconds.

Our `FlowEvent` adapter normalizes this to duration, directional counters,
UTC timestamp and lowercase categorical state. It does **not** guarantee
semantic equivalence between Argus/Bro-derived UNSW fields and future
production Zeek/Suricata/Ton captures. In particular, raw numeric destination
port and sensor-specific connection-state categories are subject to shift.
This motivated research ablations; it does not establish their effectiveness.

Do not upload or publish copies of the R2 ZIP. No raw traffic is committed
to the public GitHub repo or preserved as workflow artifacts.


## Stage 3 — authentic same-UNSW cross-capture result (2026-10-16)

Source of truth: [GitHub Actions run 38887189041](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/38887189041),
aggregate research artifact **12040032406**; **39 regression tests and Ruff passed**,
SHA-pinned authenticated UNSW source download verified, then all three
additional members were fully scanned. No raw network records were uploaded.

Predeclared metrics for the original feature-v1 supervised RandomForest:

| Capture | After exact-overlap exclusion | Benign | Attack | TN | FP | FN | TP | FPR | FPR Wilson 95% upper | Recall | Recall Wilson 95% lower |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| UNSW 2 | 7,940 | 7,365 | 575 | 6,980 | 385 | 6 | 569 | 5.2274% | 5.7595% | 98.9565% | 97.7423% |
| UNSW 3 | 7,703 | 6,083 | 1,620 | 4,783 | 1,300 | 10 | 1,610 | 21.3710% | 22.4191% | 99.3827% | 98.8674% |
| UNSW 4 | 7,579 | 6,176 | 1,403 | 4,875 | 1,301 | 5 | 1,398 | 21.0654% | 22.1002% | 99.6436% | 99.1684% |

The state-ablated port-bucket RF shows the same pattern:

| Capture | FP | FN | FPR | FPR Wilson 95% upper | Recall |
| --- | ---: | ---: | ---: | ---: | ---: |
| UNSW 2 | 391 | 6 | 5.3089% | 5.8446% | 98.9565% |
| UNSW 3 | 1,311 | 12 | 21.5519% | 22.6029% | 99.2593% |
| UNSW 4 | 1,318 | 8 | 21.3407% | 22.3801% | 99.4298% |

**Critical: both candidates FAIL the predeclared FPR 95% upper ≤5%
criterion on EVERY stress capture.** High attack recall does not offset
this failure. Stage 2 grouped-development RF FPR=4.5801% gave
misleading optimism about portability; the 3 additional raw CSV parts
expose severe within-lab distribution shift. This is stronger evidence
of a generalization blocker, **not independent-site certification**.

Source ZIP provenance remains fixed at
`3c7500f120405b21b44a2bf05134f49491f88a655ae3091fc1b269c4c9ece79a`.
The Stage 3 protocol SHA-256 was
`507a0a82e3c95ff5f7604f226bdca20e9f69689722d23d1057fd0bc38ee77891`.
Source-1 FIT is a sampled, host-pair-grouped subset; overlap removal
against captures 2/3/4 excludes only exact sampled normalized records,
not all overlapping hosts or correlated flows.

**NO-GO consequence:** Do not select RF v1 because it passed Stage 2,
do not increase a threshold based on captures 2–4, and do not claim
a model is frozen, field validated, signed/active, or ready to merge
as P0 acceptance. The already-inspected TON target is similarly
unusable as a pristine acceptance holdout. Future alternative training
designs may *treat these exposed captures as development/training only*
if declared explicitly in advance, but an independently acquired and
held-out site is still required for defensible acceptance.

### Release/acceptance blocker status

- [x] R2 source object and per-byte SHA-256 integrity evidence
- [x] Source-only feature audit, honest class support and fixed benchmark protocol
- [x] Real within-UNSW cross-capture stress: **executed, quality gates FAILED**
- [x] Report-only fail-closed NO-GO logic, never automatic model promotion
- [ ] Training strategy robust to source capture shifts; not demonstrated
- [ ] Frozen reviewed signed artifact with approved provenance/ledger
- [ ] Untouched independently operated, independently labeled site evaluation
- [ ] Active deployment equivalence, per-day/site false alerts and analyst review
- [ ] Compromised R2 upload token rotation and separate scoped read-only CI credential

Note: A GitHub Actions *green* research job means the predetermined
measurement and report executed correctly. It is **not** a green
production deployment or external ML acceptance check.
