# External network dataset audit — 2026-10-14

**Status:** Real archival file structure and bounded samples have been inspected.
**No model has been fitted or benchmarked on these external datasets yet.**
Source CSV/ZIP bytes were not committed to this repository. The temporary GitHub
Actions runner downloaded publicly shared archives and discarded raw bytes after
inventory. Small machine-readable audit manifests were retained temporarily as
short-lived CI artifacts.

## Dataset 1 — 3,372,478,580-byte archive

- Original container: `OneDrive_1_9-14-2026.zip`.
- Files: `Network_dataset_1.csv` through `Network_dataset_23.csv`, all CSV.
- **22,339,044 physical lines** across 23 files, including 23 headers; thus
  approximately **22,339,021 records** if rows have no embedded line breaks.
- 22 files have **46 columns**; `Network_dataset_6.csv` has **47** because
  it additionally provides a `uid` field after `ts`.
- Schema: `ts`, source/destination IP/port, protocol, service, duration,
  sent/received bytes/packets, connection state, DNS, SSL, HTTP,
  `weird_*` signals, binary `label`, multiclass `type`.
- **Very strong TON-IoT Network schema match** to published ToN_IoT network
  feature lists. The official TON-IoT publisher identifies Zeek/Bro CSV logs:
  https://research.unsw.edu.au/projects/toniot-datasets
  The ZIP has generic renamed files and **has not been byte-hash matched**
  to an official publisher archive; therefore do not call provenance verified.
- Sampled Unix timestamps span approximately **2019-04-02 to 2019-04-29
  UTC**. The sampling is not a full chronology audit.
- Deterministic **five byte windows per file, 96 lines each** yielded 11,040
  structurally readable rows, zero column-count mismatches in those windows.
  Of sampled rows, 388 had `label=0` and 10,652 had `label=1`.
  **This is a deliberately stratified byte-window sample, not a validated
  population attack prevalence.** Observed `type` values include `normal`,
  `scanning`, `ddos`, `dos`, `xss`, `password`, `backdoor`, `injection`.
- **Highest integration value:** near-native Zeek-like canonical fields and
  rich protocol context for behavior analytics and SOC attack classification.
- **Required engineering work:** dedicated TON-IoT CSV adapter (not direct
  reuse of Zeek JSON `id.orig_h` parsing); normalize optional `uid`,
  `-`/blank missing values, UTC timestamps, canonical source/destination
  mapping, labels separate from features. Avoid target or IP identity
  leakage; train benign-only, calibrate on distinct benign observations,
  hold out capture/time windows and at least one attack class where viable.
  Especially examine unusually attack-heavy windows.

## Dataset 2 — 586,382,286-byte archive

- Original container: `OneDrive_2_9-14-2026.zip`.
- Five files: `UNSW-NB15_1.csv`, `UNSW-NB15_2.csv`,
  `UNSW-NB15_3.csv`, `UNSW-NB15_4.csv`, plus
  `NUSW-NB15_features.csv` (the exact source spelling).
- 2,540,047 physical lines across the four **headerless** traffic CSVs,
  with approximately **2.54 million traffic records**. Do not treat all
  physical lines as certified logical row counts; confirm the few blank
  rows/line endings with a complete CSV parser.
- Feature dictionary defines **49 columns**. The raw records have source/dest
  IP/port, protocol, byte/packet counters, `Stime`/`Ltime`, attack
  category and binary `Label`. The four CSVs contain **data on row one**;
  `csv.DictReader` without `fieldnames` would silently drop the first flow.
- Sampled capture times span approximately **2015-01-22 to 2015-02-18
  UTC**. Validate chronology and any site/session boundaries separately.
- A deterministic sample of 1,920 rows across files showed 1,693 benign,
  227 attacks, and zero sampled column-count mismatches. Seen attack types:
  `Generic`, `Exploits`, `Fuzzers`, `Reconnaissance`, `DoS`,
  `Shellcode`, `Backdoor`. **Sample counts are not full class prevalence.**
- Official dataset documentation:
  https://research.unsw.edu.au/projects/unsw-nb15-dataset
- **Highest integration value:** genuine offline 49-feature intrusion
  baseline and time-indexed study, plus an alternate source distribution.
- **Required engineering work:** new raw-UNSW 49-column loader with dictionary
  mapping, normalization, timestamp-aware partition and duplicate/group
  checks. Existing `benchmark-unsw` deliberately expects different,
  header-bearing `UNSW_NB15_training-set.csv` and
  `UNSW_NB15_testing-set.csv`; **do not pass these four raw files directly
  to that runner** or invent missing preprocessing.

## Dataset 3 — 235,102,953-byte archive

- Original container: `MachineLearningCSV.zip`, inspected locally.
- Eight `MachineLearningCVE/*workingHours*.pcap_ISCX.csv` files from
  Monday–Friday of CIC-IDS2017.
- 2,830,751 physical CSV lines, including eight headers; approximately
  **2,830,743 logical flow rows** (subject to complete CSV parsing).
- Files have **79 columns** with a whitespace-prefixed `Label` header.
  Current `benchmark-cic` normalizes header whitespace and reads the
  standard CICFlowMeter required numeric columns.
- **Highest immediate benchmark readiness:** existing CICFlowMeter evaluation
  adapter can run on distinct day-based CSV partitions, with fixed seeds,
  duplicate checks, benign-only calibration and IF/LOF/rule comparisons.
- **Required evaluation:** select independent capture-day training and test
  files; inspect per-day normal/attack distribution, NaN/Infinity and
  cross-capture host/time leakage. Current code cannot prove independent
  original capture sites.

## Comparative readiness

| Dataset | Schema access | Existing runner | First priority |
| :--- | :--- | :--- | :--- |
| 1: TON-IoT-like, ~22.3M | 46/47 header-bearing columns, timestamps, labels, rich Zeek-like metadata | **New adapter needed** | Highest for #4 real-time mapping and #10 intelligence |
| 2: UNSW-NB15 raw, ~2.54M | 49 headerless columns + dictionary, timestamps, labels | **New raw adapter needed** | Highest for #1 independent timestamp-aware benchmark |
| 3: CIC-IDS2017 FlowMeter, ~2.83M | 79 header-bearing columns with labels | **CIC benchmark exists** | Fastest first external baseline |

**Do not merge the 46/49/79 feature spaces as though the meaning of counters,
durations or derived fields were identical.** Train distinct dataset-specific
models and report domain shift; map only carefully defined canonical fields to
the live-flow pipeline. No synthetic benchmark score can stand in for real
external evaluation. IP addresses, identifiers, timestamps or fields encoding
the answer must not become shortcuts for class prediction.

**Audit run:** GitHub Actions workflow
https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/38458715795

**Ethics and distribution:** Official UNSW pages describe academic
use and specific commercial permission requirements. Do not redistribute
these user's source archives or embed packet/flow rows in the public repository.
Check each source's specific terms before commercial redistribution or training
for commercial service.

## Operational notes

`tools/audit_external_dataset_zip.py` is a metadata-only scanner. Its
temporary download must be authorized and publicly accessible to the runner;
the upload artifact contains only file inventory, header samples and
window-sampled aggregates (no raw IP addresses or traffic rows). Workflow
inputs should not be used for confidential/private datasets. The workflow
runs **only when manually dispatched**, preventing recurring gigabyte
downloads on ordinary pushes.
