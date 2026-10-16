# Pre-registered V2 source-generalization test — two fresh IoT lab captures

**Registered before downloading/scoring the new capture labels.**

The new V2 missingness-aware RandomForest is frozen from **46,696 genuine
development flows** from **previously exposed** UNSW (23,551) and
IoT-23v2 Capture **34-1** (23,145). Its approved research artifact SHA is
`a1b90b4f26b98cfa00b65fd218d90ef5af97e800cf636ecfe8fa5620be6c4589`.
Training proof: [real GitHub CI run 38905158500](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/38905158500).

The model and its predeclared decision threshold **0.5** MUST NOT be changed
after retrieving new target labels. The two designated previously uninspected
capture scenarios are, in declared fixed order:

1. **IoT-23v2 CTU-IoT-Malware-Capture-8-1**, Hakai:
   https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-8-1/2018-07-31-15-15-09-192.168.100.113-zeek-conn-log.labeled
2. **IoT-23v2 CTU-IoT-Malware-Capture-20-1**, Torii:
   https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-20-1/2018-10-02-13-12-30-192.168.100.103-zeek-conn-log.labeled

The two official directories report roughly 1.4 MB and 410 KB respectively.
Both are malicious-capture research scenarios and their benign/attack
distribution has **not** been checked at registration. If there are fewer
than 200 benign or 100 attack natural scored flows, declare binary
confidence-bound metrics **BLOCKED**, not PASS.

The evaluation will:
- SHA256-lock each source before opening labels; abort on HTTP errors, malformed
  Zeek schema or file-size-limit violations; record exact source hash
  in aggregate reports.
- Reject missing mandatory host/port/time identity; missing numeric
  duration/counters remain explicit masks under versioned V2 feature contract.
- Reject flow-level exact duplicates and any canonical key collision with
  Capture 34-1 source training data.
- Never use target labels to fit a vectorizer, update RF trees,
  choose a threshold, tune hyperparameters, select the "good" capture,
  or learn an imputation rule.
- Report both targets, including unsupported/blocked cases, all flow
  coverage counts, confusion, per-class support, observed FPR/recall,
  Wilson 95% bounds and the predeclared *descriptive* thresholds.
- Never upload original IPs, UIDs or raw target rows.

**This is NOT independent physical-site or production SOC acceptance.**
Both additional targets belong to the SAME Stratosphere IoT research
laboratory family as the supervised Capture 34-1 training data. Labels are
researcher rule-assisted. Even numerical success in these two captures
cannot certify a signed active deployed model, site/day alert burden, or
independently operated field network. This is only a lab-capture generalization
sanity test, and no further tuning on its newly exposed scores is allowed
without explicitly converting these captures to development-only status.
