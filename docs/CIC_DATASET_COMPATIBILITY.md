# CIC-IDS2017 external FlowMeter CSV evaluation

**No real dataset is bundled.** Operator-supplied CIC-IDS2017 FlowMeter CSVs must be obtained under their licensing conditions from the official Canadian Institute for Cybersecurity dataset site: https://www.unb.ca/cic/datasets/ids-2017.html

```powershell
networkpulse benchmark-cic --train path/to/capture-day-train.csv --test path/to/independent-test-day.csv --output reports/cic-benchmark.json
```

The adapter validates and uses these CICFlowMeter columns: `Flow Duration` (microseconds), `Total Fwd Packets`, `Total Backward Packets`, `Total Length of Fwd Packets`, `Total Length of Bwd Packets`, `Destination Port`, `Label` (column aliases handled). It does **not** reinterpret these as Zeek/Suricata canonical flows, and never invents absent IP/timestamps. Invalid numeric values (NaN, inf, negatives, gross out-of-range) are skipped with counts in the report.

The evaluator uses a benign-only seeded fit/calibration subset of the supplied training file and a **distinct operator-supplied test file**, with cross-partition deduplication by feature fingerprint. Isolation Forest, novelty-mode LOF and a simple rule baseline are evaluated with F1, precision, recall, FPR, ROC-AUC, PR-AUC and confusion-matrix metrics. Test labels are only used after training and calibration. Metadata records input SHA-256, sample cap and invalid/duplicate rows. When the user supplies multiple capture-day files, the operator must explicitly choose disjoint capture sources; **the code cannot prove their independence**.

**IMPORTANT:** Local pytest fixtures are synthetic CSV rows that mimic the CIC schema; they do not validate CIC-IDS2017 detection performance. Real evaluation results should be uploaded/reviewed before any accuracy or deployment suitability claim. Group/time/site leakage, unseen attacks and shift across networks need dedicated externally grounded experiments.
