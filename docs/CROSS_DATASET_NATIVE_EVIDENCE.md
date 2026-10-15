# P0 native cross-dataset research evidence: UNSW -> TON-IoT

This workflow trains a NEW research-only NetworkPulse native Detector on authentic earlier UNSW raw flows (UNSW-NB15_1.csv), fixes a previously studied benign quantile of 0.995 before TON inspection, serializes and reloads that frozen model, and applies it once to a different published data family: TON-IoT Network_dataset_23.csv. No TON test labels or test-domain scores influence model fitting, threshold calibration or source feature selection.

Input source ZIP hashes are pinned and must match previously measured real archives. TON source metadata fields are validated against the actual native FlowEvent contract. Missing IP, timestamps, ports or counters cause rejection, not invented values. Full source CSV scanned; seeded uniform 5000-row sample, source-neutral duplicate removal, disjoint event IDs and time separation. Only private raw data is processed on temporary GitHub Actions runners. Published evidence contains aggregated FPR, recall, F1, PR-AUC, ROC-AUC, per-day confusion matrices, 95% Wilson intervals, per-10000 benign false-alert burden and research model checksum.

PREDECLARED operational acceptance: FPR 95% Wilson upper <=5% AND recall lower >=80%. A green GitHub workflow means a valid experiment ran; it must not be conflated with a passed accuracy gate. Failures remain recorded and will NOT be used to tune the source-trained model on external target labels.

LIMITATIONS: the test model is newly trained, not the user's preexisting signed production artifact; dataset-family separation is not proof of audited independent physical-site deployment or human-revalidated labels. TON and UNSW sensors may record counter semantics differently. Single TON capture, correlated hosts/flows, and uniform reservoir cannot support full field-level calibration or multi-site replication. No SOC wall-clock hourly alert burden is measured. To claim production acceptance, obtain actual approved frozen-model bytes and independently authorized labeled live-site Zeek/Suricata capture and run signed external evaluation plus staging acceptance.


## Measured research outcome — GitHub Actions 38773109952 (15 Oct 2026)

**Execution:** [Verified GitHub Actions run](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/38773109952); the real-dataset job completed successfully and uploaded `real-independent-dataset-native-evidence` with the original aggregate report. The artifact's extracted JSON SHA-256 is `98eac6edb3a05f23902b00a09f09d3e8675b2a79f8f0062f273ee05aff6951e2` (this is NOT a cryptographic signature). Job commit: `86bfa4378a594660726b84230aa02c66805d8437`. It precedes Ruff-only refactoring of source formatting.

| Held-out TON sample, *uniform without label stratification* | Result |
|---|---:|
| Original valid TON capture rows fully scanned | 339,017 |
| TON evaluated sample | 5,000 |
| Benign / attacks | 480 / 4,520 |
| True negatives / false positives | 375 / **105** |
| False negatives / true positives | 13 / **4,507** |
| False-positive rate | **21.875%** |
| 95% flow-level Wilson FPR interval | **18.408%–25.7886%** |
| Attack recall | **99.7124%** |
| 95% flow-level Wilson recall interval | 99.5085%–99.8318% |
| Precision / F1 | 97.7233% / 98.7078% |
| PR-AUC average precision / ROC-AUC | 0.982494 / 0.928690 |
| False alerts per 10,000 benign flows | ~**2,187.5** |
| Predeclared 5% FPR + 80% recall operational gate | **FAILED** |

Training: 2,200 earlier UNSW flow sample; 2,197 unique flows after dedup. Frozen research model SHA-256 from this run: `fe8808ea72143fdc2772ffabad0a30f038aada38f827ee0208627c65d1735cb1`. TON source SHA-256: `411ec9768cc06586265095292f3fdc78f10306d26c9e4e227079f7c286520ad0`. UNSW source SHA-256: `3c7500f120405b21b44a2bf05134f49491f88a655ae3091fc1b269c4c9ece79a`.

**Interpretation:** This is real cross-*dataset* evidence showing that the native model fails the predeclared benign false-alarm target under a different research network. The unusually high 90.4% attack fraction inflates precision and PR-AUC compared with ordinary low-prevalence SOC traffic. Day-specific benign FPR was 13/44 (29.55%) on 2019-04-28 and 92/436 (21.10%) on 2019-04-29; day 1 benign support is small. The flow-level confidence interval cannot correct host/session correlation. Do not convert this failing study into a production approval or silently optimize this already inspected TON capture; any revised candidate requires an untouched independent test source.
