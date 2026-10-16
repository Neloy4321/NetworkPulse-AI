# Frozen calibrated V2 — prospective same-laboratory transfer test preregistration

Created **before retrieving any new labeled target flow rows**. Registered
model: exact unsigned source-calibrated SHA
`cd239783fd4318c0c4e897f1d451c2d5af4b42132979c79a4e489df626f538a5`
with immutable threshold **0.20** selected only from exposed UNSW and IoT-23v2
Capture 34-1 development groups. Never choose a better cutoff using targets.

Declare TWO new fixed IoT-23v2 scenarios before any data access:

1. **CTU-IoT-Malware-Capture-42-1** (Trojan; official Zeek labeled file
   `2019-01-10-14-34-38-192.168.1.197-zeek-conn-log.labeled`,
   572 KB, ~8.35 hour scenario)
   https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-42-1/
2. **CTU-Honeypot-Capture-4-1** (Philips Hue benign; official
   `2018-10-25-14-06-32-192.168.1.132-zeek-conn.log.labeled`,
   60 KB, ~21.90 hour scenario)
   https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-Honeypot-Capture-4-1/

The two sources are different captures from the **same CTU Stratosphere lab
and dataset family**, not a true independent operator/production SOC.
Hakai 8-1 and Torii 20-1 have already been exposed and are NOT used here.

Protocol: source-first SHA256 of each entire original log (record before
reading labels); exact unchanged model SHA and training protocol check before
any target inference; reject duplicate/corrupt flows or sensor values; use
versioned masked V2 features for all intact records, no missing-value
imputation; score BOTH named captures with one fixed threshold; report
benign/attack class support per capture and combined. If combined natural
benign support <200 or attack support <100, numerical status BLOCKED.
Otherwise report TN/FP/FN/TP, Wilson 95% upper FPR against <=5%, Wilson
95% lower recall against >=80%. No model fitting, no test-set threshold
optimization, no suppression of unfavorable captures. Test result is a
**public laboratory benchmark** and cannot approve a signed production
model or replace independently operated field network evidence.
