# Later-day transfer recheck — fixed IoT-SFC v7 research ExtraTrees

**Purpose:** test the *same* ExtraTrees artifact that already achieved
**aggregate FPR upper95 4.1714% / recall lower95 98.7775%** on earlier
Apr 12–14, without retraining or choosing a new cutoff. The original frozen
RandomForest baseline remains separate and unchanged.

Candidate SHA256:
`ecc320bc693481fc45b143b48ffbebcb117899e888e4687930f3361501af6fa1`.
Candidate cutoff: **0.90**.
Original dataset SHA256:
`070b1356e5bd296e584109fae79139cfe0f20ff4790f69e42994d67362cb9f62`.

New *prespecified* review slice: UTC **Apr 15, 16, 17, 2025**.
Original source FIT ≤Apr 8; calibration Apr 10; previous pointwise check
Apr 12–14. Reject all raw rows outside the fixed date range and all
non-`conn` log types. Skip the already exposed first **450,000** CSV
records before analyzing this stress window.

**Bounded and candid:** stream no more than **9 million** source CSV
records after the source prefix; retain the **first 60,000 validated, unique
candidate flows per UTC day**. This is not a random, entire-population
holdout or independent lab/site. Report exact eligible support and rejection
counts. Do NOT silently claim a missing date or attack support is a PASS.

The producer's binary `attack` labels are not independent reviewed ground
truth. This experiment does not authorize live model promotion or any
operator signature. It produces day-level confusion, pointwise Wilson FPR
upper95 and attack-recall lower95 where class support permits. Cluster-aware
uncertainty and true cross-lab generalization remain unverified.

GitHub Actions:
`.github/workflows/p0-iot-sfc-later-day-locked.yml`.
Artifact:
`iotsfc-apr15-17-locked-extra-trees-aggregated-no-raw`.
Sensitive bytes are isolated on the runner, SHA-verified and deleted. Only
aggregated metrics remain.

**Independent operational ML acceptance: NO-GO until** externally
collected human-adjudicated flow labels, genuinely independently operated
site, signed and human-approved artifact, HTTPS/OIDC active deployment,
real Zeek/Suricata parity, and reviewer assessment of alarm rates on actual
workload. Lab numerical PASS alone does not cover those gates.
