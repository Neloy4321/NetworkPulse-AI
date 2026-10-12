# UNSW-NB15 external benchmark: methodology and reproducibility

**Release scope:** Implements a reproducible benchmark *runner*. An official-data score is **not shipped or claimed** until the official CSV files have been legitimately obtained and the exact run has completed with a preserved checksum report.

## Source and permitted use

- Official dataset: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- Authors: Nour Moustafa and Jill Slay (MilCIS 2015), plus follow-on papers noted by UNSW.
- UNSW states academic use is granted, and commercial use needs agreement with authors. We do **not** redistribute these datasets in the repository.
- Use `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv` from the official distribution, with their actual filenames and headers.

## Exact command

```bash
python -m pip install -e '.[dev]'
networkpulse benchmark-unsw \
  --train data/external/UNSW_NB15_training-set.csv \
  --test data/external/UNSW_NB15_testing-set.csv \
  --max-train 15000 --max-test 12000 --seed 42 \
  --output reports/unsw-benchmark.json
```

This command does **not** train the deployed Zeek/Suricata model or overwrite `data/model.joblib`. It writes a JSON report containing the file SHA256 hashes, sample method, sample counts, duplicate exclusions, per-model metrics, per-category recall and limitations. Uncapped run: `--max-train 0 --max-test 0`, but LOF may be expensive.

## Methodologically valid comparisons

| Comparison | What it measures | Conditions |
| :--- | :--- | :--- |
| Isolation Forest | Unsupervised novelty with independent benign calibration | Train only on benign labeled rows from published train split |
| LOF novelty | Local-density novelty baseline | Fit only training benign, then score unseen test rows |
| Rule baseline | Fixed thresholds on outbound volume, response fraction and duration | Does not optimize thresholds using test labels |

Both trained estimators use the **same** subset of network-flow numeric/categorical fields available in prepared UNSW data. All fitted encoders and robust scalers use the training fit subset only. Calibration is conducted only on a distinct benign slice of the official training set. Evaluation uses the separate official test partition. Exact duplicate fingerprints are excluded across partitions; emitted counts disclose what was removed.

**Classification metrics:** precision, recall, F1, confusion matrix, false-positive rate, PR-AUC and ROC-AUC. Per-attack recall is provided where labels exist. ROC-AUC/PR-AUC require both classes. Fixed random seeds make row sampling reproducible.

## Mapping caveats (critical)

The UNSW *prepared partition CSVs* do not provide trustworthy Zeek-style source IP, destination IP, destination port and event timestamps. Their rows are **not** converted to canonical `FlowEvent` by inserting invented values. The benchmark trains an **isolated model with a compatible subset of numeric fields**. It does not report what the deployed flow model would achieve on this dataset.

The published prepared train/test split is **not a verified chronological or cross-site split**. This is disclosed as `temporal_split_verified=false` and `cross_site_shift_verified=false`. For actual time-aware and unseen-site verification, use independently labeled, timestamped sensor logs, ideally from distinct capture periods and sites, with stable data provenance and a designated held-out attack family.

**Reproduction gates:** preserve source URL, distribution terms, checksums, capture provenance, sampling counts, class distribution, duplicate counts and failure cases. Never publish real benchmark scores from the included synthetic unit-test fixtures.
