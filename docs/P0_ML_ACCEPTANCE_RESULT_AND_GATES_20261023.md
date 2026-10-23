# NetworkPulse-AI — P0 ML acceptance decision (real evidence, 2026-10-23)

## What actually PASSED

The **new** `ExtraTreesClassifier` research candidate trained on authorized IoT-SFC v7 laboratory connection flows and selected at fixed cutoff **0.90** on a *preceding development day* has achieved the **two aggregate flow-level pointwise Wilson 95% numerical targets** on later same-laboratory days.

| Item | Real value | Gate |
| --- | ---: | --- |
| Benign support | 125,226 | >=200 |
| Attack support | 216,533 | >=100 |
| TN / FP / FN / TP | 120,141 / 5,085 / 2,547 / 213,986 | Grounded |
| Observed FPR | **4.0607%** | — |
| FPR Wilson 95% upper | **4.1714%** | **<=5%: PASS aggregate** |
| Observed attack recall | **98.8237%** | — |
| Recall Wilson 95% lower | **98.7775%** | **>=80%: PASS aggregate** |
| Actual assessed dates | Apr 12, 13 and 14, 2025 | 3 dates, but one has **1 benign** |
| Model | New ExtraTrees SHA `ecc320bc693481fc45b143b48ffbebcb117899e888e4687930f3361501af6fa1` | Unsigned research only |

The earlier **separately frozen** source-calibrated RandomForest model SHA
`cd239783fd4318c0c4e897f1d451c2d5af4b42132979c79a4e489df626f538a5`
with threshold **0.20** was **not** changed or falsely promoted. On these
identical test flows its FPR was **94.7790%** (95% upper 94.9009%) and attack
recall **98.0396%** (95% lower 97.9803%). The new ExtraTrees cutoff **0.90**
was selected on Apr 10 source DEV; Apr 12+ target labels did not select it.

**Original evidence:**
- [PR #41 — FPR repair, merged](https://github.com/Neloy4321/NetworkPulse-AI/pull/41)
- [Real forward-day run #39921326610](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/39921326610)
- Run artifact **12487502789**, `iot-sfc-forward-day-numerical.json`,
  inner-file SHA-256 `4c80e0a068cd623edbf612daf38037544fd1f1908fba70392c4e6b525920dc49`
- Separately frozen *unsigned* candidate run artifact **12487143959**,
  inner-file SHA-256 `ecc320bc693481fc45b143b48ffbebcb117899e888e4687930f3361501af6fa1`.
  Binary is **not** committed to Git, automatically signed, or deployed.
- Exact original Zenodo v7 archive SHA-256:
  `070b1356e5bd296e584109fae79139cfe0f20ff4790f69e42994d67362cb9f62`.
  The user reports rights holder permission to research using this dataset
  **with citation**. Cite [Zenodo 23371775](https://zenodo.org/records/23371775).

The report's metadata and every count are pinned in
[`P0_IOT_SFC_V7_VERIFIED_NUMERIC_GATE_20261023.json`](P0_IOT_SFC_V7_VERIFIED_NUMERIC_GATE_20261023.json),
with tests that recompute Wilson intervals and **reject false GO claims**.

## What did NOT pass / is not yet demonstrated

**Full operational P0 = NO-GO.**

- Apr **13** benign FPR = **7.0086%**, Wilson 95% upper **7.2086%**.
  This exceeds 5% even though the aggregate 4.17% bound passes.
- Apr **12** has **0 attack** rows, so recall cannot be assessed that day.
  Apr **14** contributes **1 benign** and 0 attack. Only one of these dates
  has both natural class types. A cluster/day-aware confidence interval
  cannot be inferred from 341,759 correlated flows alone.
- The development split was chronological, but **121,320** source Apr 10
  DEV rows share hostpair/protocol groups with preceding FIT. The final
  test has no attack support in its previously unseen hostpair/protocol
  slice; this does not prove generalization to unseen attacking hosts.
- Dataset's `attack` / `type_of_attack` labels were **producer supplied**,
  *not independently human adjudicated against sensor events*. Per-flow
  provenance is not a signed independent site observation.
- It is the same public IoT-SFC laboratory family used to fit/calibrate the
  new model, not a **physically independent operational site**.
- Model is not a human-approved Ed25519-signed release, not the active V2
  server and not validated end-to-end over a **real TLS/OIDC protected
  deployment** with authentic Zeek/Suricata alerts and operator false-alert
  review.

These limitations prevent turning a real **aggregate research result** into
a fictional **production or field ML acceptance**. Do NOT merge/relabel the
unsigned research candidate as the live approved detector. Do NOT silently
adjust model/cutoff using held-out Apr 12–14 results and retest those days
as a fresh blind dataset.

## Remaining acceptance work (in execution order)

1. Freeze/version the **new** ExtraTrees research artifact and the exact
   feature preprocessor/threshold **0.90**; require real model reviewer
   authorization before signing. Existing RandomForest version stays separate.
2. Validate **independent row ground truth** against Zeek sources/attack-window
   metadata and real human labels; review hostpair/day clustering and the
   Apr 13 high-FPR segment. Do not call that day PASS.
3. Obtain a **genuinely independent field-site or source-family** prospective
   holdout with enough benign and attack support and evaluate the locked model
   on it, without target-guided tuning.
4. Upon verified quality on independent data, complete real model approval,
   Ed25519 signature, authenticated HTTPS/OIDC staging and live traffic parity;
   record real alert volume, latency, rollback and independent operator receipt.

The fact that all GitHub unit/quality workflows are green proves the code
runs—not that an operator has accepted the model.

**Release classification:** `AGGREGATE_NUMERICAL_RESEARCH_PASS`;
`OPERATIONAL_ML_P0=NO_GO`.


## Follow-up AFTER the original 12–14 April aggregate result: further-date Recall FAIL

The separately pinned original ExtraTrees SHA `ecc320bc...1501af6fa1`, unchanged
cutoff **0.90**, was evaluated on previously unscored **April 15–17** genuine
IoT-SFC v7 `conn` rows in [Actions run #39925211304](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/39925211304).
This run did **not** retrain or choose a new cutoff. The scan was predeclared:
exclude the first 450,000 source rows, scan the next 9,000,000 raw rows and
retain at most the first 60,000 eligible unique connections per target UTC day.
Thus the result is a bounded later-day *same-lab* stress sample, not a
random/population-complete independent-site test.

Actual 156,362 scored, producer-label rows: **TN 155,221 / FP 119 /
FN 432 / TP 590**. Observed benign **FPR 0.0766%**, Wilson upper95
**0.0917%** (meets FPR criterion); attack **recall 57.7299%**,
Wilson lower95 **54.6779%** (**FAILS >=80%**).

Per-day **April 15 recall 26.36%** on 569 attacked flows (419 missed);
April 16 has just 1 attacked flow and cannot establish recall; April 17
recall 97.12% on 452 attacks. This domain/day shift is unacceptable as
evidence of stable generalization. A low false-alarm rate alone cannot
offset many missed attacks.

Immutable summary and raw artifact SHA:
[`P0_IOT_SFC_V7_APR15_17_LOCKED_RECALL_FAILURE.json`](P0_IOT_SFC_V7_APR15_17_LOCKED_RECALL_FAILURE.json).
GitHub run artifact ID **12488319488**, inner aggregate JSON SHA-256
`5c3ff1101a64ddab20ac45229122ec12c4cd5f13bf47561f06af3f2e5bafc004`.

**Updated research validation conclusion:** previous Apr 12–14 aggregate
pointwise numeric PASS remains a valid historical observation. But the
following fixed later-day validation **FAILS Recall**, so no robust ML
acceptance can be asserted even within this public laboratory family.
No signed production promotion, operator receipt or independent field
endorsement should occur. Future repair may use *exposed* days as
development only; reserve new independent untouched test captures.
