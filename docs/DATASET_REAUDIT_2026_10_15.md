# P0 dataset ZIP re-audit and archive-structure controls — 2026-10-15

**Status: PARTIAL new audit; full P0 field-site acceptance NOT DEMONSTRATED.**
This note separates current direct inspection from previously archived GitHub Actions
metadata; it does not represent a new complete read of the two large archives.

## Original user-provided archives

| Dataset | Drive file ID | ZIP size | SHA-256 provenance | Inventory evidence |
|---|---|---:|---|---|
| TON-IoT-compatible, generic name | `1rkNwQzrkpcnmtM8G5a-O7dAtr-y_9wFy` | 3,372,478,580 | `411ec9768cc06586265095292f3fdc78f10306d26c9e4e227079f7c286520ad0` (previously recorded) | 2026-10-13 Actions `38458715795`, artifact `11843958936` |
| UNSW-NB15 raw | `16eIgENKYpiLwJNHZWRrYdPfGj6AOOtkT` | 586,382,286 | `3c7500f120405b21b44a2bf05134f49491f88a655ae3091fc1b269c4c9ece79a` (previously recorded) | 2026-10-13 Actions `38458715795`, artifact `11844431806` |
| CIC-IDS2017 FlowMeter | `1OLwT2I4sueiDJAO_ys_sn_2CO60OveBN` | 235,102,953 | `c3f26274b36c837ccf28ffd2dbf4582941c30b3ee70a635c6e5b2f87c4727928` (**newly locally recomputed**) | **Current direct ZIP and full eight-CSV scan** |

Original URLs are documented in the project's handoff and older audit, not repeated
as CI secrets. All archives remain third-party research dataset material. Do not
publish original flow rows, identifying addresses, the archives, or private labels.

## ZIP path tree, including nested folders

- **TON:** archival metadata shows 23 root-level CSVs named
  `Network_dataset_1.csv` through `Network_dataset_23.csv`, no nested
  directory in that recorded ZIP. There are 22,339,044 physical newline counts,
  including 23 header records (~22,339,021 possible data records, NOT a certified
  logical CSV count). 22 members have 46 headers; member `_6` has 47 due to
  extra `uid`. Byte-window samples had 388 benign / 10,652 attacks **in
  nonrepresentative deterministic samples**, not measured overall prevalence.
  Generic filenames and schema resemblance do **not** independently verify
  publisher/source or site provenance.
- **UNSW raw:** archival metadata shows 4 root-level *headerless* traffic CSVs
  (`UNSW-NB15_1.csv` to `UNSW-NB15_4.csv`) plus root
  `NUSW-NB15_features.csv` (literal misspelling). Dictionary defines 49
  columns. Prior manifest counted 2,540,047 physical lines (not certified
  logical row count). 1,920 deterministic window-sampled flows were 1,693 benign
  / 227 attacks; do not call this population prevalence. The first row of each
  raw capture is data and must **not** be treated as a header.
- **CIC:** locally verified root directory `MachineLearningCVE/`, containing
  exactly eight CSV members, all 79 columns with whitespace-padded ` Label`.
  This nested path **must not** be flattened or blindly treated as a root CSV.
  The directory contains no additional nested files in the checked ZIP.

The two large archives could not be re-downloaded through the current Google
Drive connector (256 MiB single-file download limit). Their member trees above
were recovered from unexpired **original GitHub Actions manifest artifacts**,
not extrapolated from filenames and not newly rescanned raw bytes. Recheck each
actual archive checksum when running a new authorized ephemeral Actions audit.

## CIC-IDS2017: actual complete local CSV row scan

All eight members were streamed with CSV parsing, not merely sampled. No
79-column row-width mismatch was found. Per-file binary benign / attack
counts and rows with literal `NaN` or `Infinity` values:

| Original member under `MachineLearningCVE/` | Records | Benign | Attacks | Literal NaN/Infinity rows |
|---|---:|---:|---:|---:|
| Monday-WorkingHours.pcap_ISCX.csv | 529,918 | 529,918 | 0 | 437 |
| Tuesday-WorkingHours.pcap_ISCX.csv | 445,909 | 432,074 | 13,835 | 264 |
| Wednesday-workingHours.pcap_ISCX.csv | 692,703 | 440,031 | 252,672 | 1,297 |
| Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | 170,366 | 168,186 | 2,180 | 135 |
| Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | 288,602 | 288,566 | 36 | 207 |
| Friday-WorkingHours-Morning.pcap_ISCX.csv | 191,033 | 189,067 | 1,966 | 122 |
| Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | 286,467 | 127,537 | 158,930 | 371 |
| Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | 225,745 | 97,718 | 128,027 | 34 |
| **All 8** | **2,830,743** | **2,273,097** | **557,646** | **2,867** |

Attack-label details verified from CSV rows: DoS Hulk 231,073;
PortScan 158,930; DDoS 128,027; DoS GoldenEye 10,293;
FTP-Patator 7,938; SSH-Patator 5,897; DoS slowloris 5,796;
DoS Slowhttptest 5,499; Bot 1,966; Web Attack Brute Force 1,507;
Web Attack XSS 652; Infiltration 36; Web Attack SQL Injection 21;
Heartbleed 11. In original archive, some Web Attack label bytes do not
decode cleanly as UTF-8: re-check and explicitly fix text decoding policy
before multiclass metrics rather than silently replacing characters.

**Data-science implications:** Monday is entirely benign, and other days
contain sharply different attack mixes. Random row splits would overstate
independence. Require day/capture-group partition, missing-value handling and
class-specific support. Standard CICFlowMeter CSVs here lack the original
source/destination IP and trustworthy native event times required by
`FlowEvent`: do **not** invent them to force a native production-score test.
Their appropriate present role is a separate-feature research benchmark.

## New code safeguards

- `networkpulse/evaluation/archive_members.py` resolves a specific
  required CSV *basename* regardless of folder depth, but refuses ambiguous
  duplicate members, archive traversal paths and symbolic links.
- `live_unsw.read_reservoir` and `unsw_to_toniot.ton_sample` now use this
  resolver. Original root-level archives work unchanged; nested descendants
  are supported without guessing.
- CSVs with extra/missing fields, or duplicate normalized TON header names,
  are rejected instead of silently corrupting native feature mapping.
- Synthetic tests validate safe nested resolution, duplicates, missing
  members, traversal and symlink attacks. Synthetic tests are *not* ML evidence.

## P0 acceptance remains blocked

Native real UNSW → TON research result from Actions run `38773109952`:
**105 / 480 benign false alarms, FPR 21.875%; 4,507 / 4,520 detected
attacks, recall 99.7124%. The predeclared FPR upper Wilson bound <=5% /
recall lower Wilson bound >=80% contract FAILED.**

A ZIP with 23 shards does **not** prove 23 independent sites; the 23 members
may share sensor, hosts, clock periods and collection provenance. The old
inspected TON `_23` cannot be tuned against and then reused as a pristine
test. A newly frozen candidate must be developed only on declared fit/
calibration data and tested against an independently acquired, untouched,
labeled source with field contract verified. The research model is not the
operator-approved signed production model. Passing CI only means executable
code and data-processing completed, **not** that real-world ML passed.

**Next dependency:** authorized untouched independent site/source and an
approved signed model artifact, then grouped uncertainty, alert burden and
accepted real staging. Until then report `P0 NOT DEMONSTRATED`, not 100%.
