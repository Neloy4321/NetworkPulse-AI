# P0 — MQTT attack-miss diagnosis from an immutable exposed IoT-SFC slice

**Status:** Validated research diagnostic, **NOT new ML acceptance**. 23 October 2026.

Run: [39943461842](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/39943461842); aggregate-only artifact **12496977415** (archive SHA-256 `afc5672b430c252a57cdb4a4de6ba59743b2b55f3b0b76cbec0ca69553f401db`). The action uses the same original source ZIP SHA `070b1356e5bd296e584109fae79139cfe0f20ff4790f69e42994d67362cb9f62`, unchanged original research ExtraTrees model SHA `ecc320bc693481fc45b143b48ffbebcb117899e888e4687930f3361501af6fa1` and unchanged **0.90** cutoff. It replayed exactly **TN 155,221 / FP 119 / FN 432 / TP 590** and April 15 **419 FN**.

## What is actually failing?

| Producer-reported attack family | Attack support | TP | FN | Observed recall |
| --- | ---: | ---: | ---: | ---: |
| `mqtt_malformed` | 420 | 28 | **392** | 6.67% |
| `mqtt_brute_force` | 19 | 0 | **19** | 0% |
| `synflood` | 574 | 559 | 15 | 97.39% |
| Other rare families combined | 9 | 3 | 6 | 33.33% |

**411/432 false negatives are producer-labelled MQTT families.** All 420 MQTT malformed attacks and all 19 MQTT brute-force attacks in this slice occurred on April 15. Service-port diagnostics showed **306 misses on destination port 22** and **126 misses on port 1883** (overlap with family counts is not a cross-tabulation). Connection-state diagnostics showed **260 misses with `SH`** and **167 with `S0`**. These are associations, not proof that fields or producer windows have correct causal attribution; raw logs/attack-window joins and independent label review are still needed.

## Fixed-model cutoff sensitivity — exposed data, not selection evidence

| Cutoff | FP / benign | FN / attacked | FPR Wilson upper95 | Recall Wilson lower95 |
| --- | ---: | ---: | ---: | ---: |
| 0.50 | 1,007 / 155,340 | 126 / 1,022 | 0.6894% | 85.5134% |
| 0.70 | 772 / 155,340 | 128 / 1,022 | 0.5332% | 85.3049% |
| 0.80 | 771 / 155,340 | 130 / 1,022 | 0.5325% | 85.0965% |
| 0.85 | 325 / 155,340 | 336 / 1,022 | 0.2332% | 64.1838% |
| **0.90 original** | **119 / 155,340** | **432 / 1,022** | **0.0917%** | **54.6779%** |
| 0.95 | 8 / 155,340 | 530 / 1,022 | 0.0102% | 45.0903% |

At **0.80**, the fixed model detects **302** more attacks across the exposed slice, but the April 15 per-day gate still cannot be established. April 15 needs at least **474/569** true positives for its own Wilson lower95 to exceed 80%, versus **150** at the frozen 0.90. Even if **all 306 additional detections** at the lowest examined 0.50 cutoff occurred on April 15, its TP would be **456**, below **474**. Therefore the evaluated cutoff choices alone cannot meet the April 15 per-day criterion.

## Correct next step

Source-only feature/model development should target the missed MQTT families and check capture-window/producer-label consistency. [PR #45](https://github.com/Neloy4321/NetworkPulse-AI/pull/45) explores bounded native Zeek service/state features with disjoint-source development checks. Neither this diagnostic nor that research experiment is a fresh independent holdout. Historical FAIL artifacts remain unchanged; **operational ML P0 is NO-GO** pending truly independent prospective data, external label adjudication, signed approved model and live operator deployment checks.
