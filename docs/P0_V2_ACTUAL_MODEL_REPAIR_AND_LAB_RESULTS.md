# P0 ML — implemented V2 sensor repair, authentic retraining and cross-capture transfer

**Date:** 2026-10-16. **Scope:** reproducible ML development using authentic
approved source bytes. **P0 operational acceptance: NO-GO** pending genuinely
independent deployment, field-labeled operator data, review and signing.

## Actual engineering completed in PR #26

1. Added versioned, opt-in `FlowV2` canonical telemetry with nullable
   duration and directional byte/packet counters. Zeek/Suricata adapters keep
   sensor `-`/null **missing** distinct from measured zero. Unknown identity
   ports/timestamps, negative and invalid numeric values fail closed.
2. Defined a single `features_v2()` function for both training and
   inference, with separate explicit missingness masks for raw and
   derived measurements. Never include ground truth, IPs, UIDs, timestamps
   or sensor-specific state vocabulary as model predictors. Legacy
   version-1 Detector and its deployed files are unaffected.
3. Actual full source audit:
   [GitHub run #38904572472](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/38904572472)
   **32 tests + Ruff passed**; **all 23,145/23,145** verified IoT-23v2
   Capture 34-1 rows parse/vectorize under V2, with **17,824**
   naturally incomplete records preserved via explicit flags,
   rather than silently removed or zero-filled. Metadata-only
   artifact: `12046704298`.
4. Authentic real-data supervised RandomForest V2 trained on **46,696**
   genuine exposed development flows: **23,551** unique UNSW-NB15 source
   rows and **23,145** IoT-23v2 Capture 34-1 labeled rows.
   [GitHub run #38905158500](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/38905158500)
   **19 focused tests + Ruff passed**, model serialized/reloaded with
   identical prediction probabilities.
   Frozen **UNSIGNED RESEARCH MODEL** SHA256:
   `a1b90b4f26b98cfa00b65fd218d90ef5af97e800cf636ecfe8fa5620be6c4589`.
   Aggregate training manifest artifact `12047602455`,
   unsigned research bundle artifact `12048086588`.
5. PRE-REGISTERED before scoring two previously unused other-lab-capture
   scenario targets, original IoT-23v2 **Capture 8-1 (Hakai)** and
   **Capture 20-1 (Torii)**, with unchanged threshold **0.5** and original
   binary requirement of 95% Wilson upper benign FPR ≤0.05 and
   95% Wilson lower attack recall ≥0.8.
   Preregistration: `docs/P0_V2_PREDECLARED_LAB_CAPTURES.md`.
   [Authentic research run #38906176832](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/38906176832)
   **7 tests + Ruff passed**; exact model SHA-256 reproduced
   BEFORE acquiring any new target labels, immutable selection preserved.
   Aggregate lab research artifact `12048088027`, no raw IPs/UIDs.

## Exact V2 two-capture results (exposed after first measurement)

| Target capture | Flows | Benign | Attack | Missing numeric | TN | FP | FN | TP | FPR | FPR 95% upper | Recall | Recall 95% lower | Result |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 8-1 Hakai | 10,403 | 2,181 | 8,222 | 6,185 | 2,179 | 2 | 1,847 | 6,375 | 0.0917% | 0.3338% | 77.54% | 76.62% | **Research numeric FAIL** (recall bound below 80%) |
| 20-1 Torii | 3,209 | 3,193 | **16** | 885 | — | — | — | — | — | — | — | — | **BLOCKED** insufficient genuine attack support |

Source SHA captured before label scoring:
- IoT v2 8-1:
  `4877ca8f0f01902fbd18d28b7d06cb3d0be082355b7f2c8862c9deef1782eb8a`
- IoT v2 20-1:
  `ef48ad72f65efd13d517223e61e4d877ba53a082ddb8159324b18d3f310d0711`

Interpretation:
- The V2 representation and actual supervised mixed-source model repair
  **resolved technical feature coverage** (100% versus 22.99% complete
  case), and achieved a low false-alarm rate on **one newly scored
  Hakai research capture**. This is **not a like-for-like comparison** with
  old IoT-23 34-1 because target distribution changed AND model retrained.
- Hakai misses **1,847/8,222** labeled attacks; current recall is
  insufficient for the predeclared criterion even though FPR is low.
- Torii has only **16** labeled attacks, so cannot support a binary
  acceptance confidence estimate; do not invent a PASS.
- All IoT captures still belong to the **same Stratosphere Laboratory
  dataset family**; research labels are not SOC/independent-operator
  adjudication. No independent field site, live alert load, uptime
  or active signed-model parity has been demonstrated.
- All of UNSW and IoT-23 Captures 34-1, 8-1, 20-1 are now **exposed
  research/dev evidence**. They must not be reclassified as pristine
  post-tuning holdouts. No threshold was tuned to new target labels.

## Next acceptance-critical engineering, in priority order

1. Improve source-side **attack recall** under fixed FPR constraints
   without tuning on the just-exposed 8-1 or 20-1 outcomes. If including
   those labels in future development, explicitly reclassify them as
   training/dev and reserve a NEW unseen verified source capture.
2. Implement production-compatible V2 scoring behind a reviewed,
   immutable **signed** model/feature contract; keep V1 as default until
   promotion approval and backward-compatibility checks.
3. Run fresh operator-approved independently labeled external-site
   evaluation and a true controlled/staged active model with
   per-day/site false-alert burden, latency, TLS, secret hygiene,
   reviewer signoff and signed artifact equivalence.
4. Rotate previously exposed R2 keys, scope CI credential to read-only.

**No promised numerical improvement is a guaranteed acceptance outcome**.
The most recent verified result is V2 **source compatibility + real training
SUCCESS**, external *research* recall condition still NOT MET. P0 **NO-GO**.
