# IoT-SFC v2 — Legal-use and CSV header compatibility audit

**Decision (2026-10-23): RIGHTS_CLARIFICATION_REQUIRED, CSV_HEADER_LOCAL_REPORT_PENDING.**
Frozen V2 RandomForest SHA256: cd239783fd4318c0c4e897f1d451c2d5af4b42132979c79a4e489df626f538a5.
Threshold: 0.20. Feature contract: missingness_aware_flow_v2. Neither changed.
**Research numerical evaluation NOT RUN; operational ML P0 NO_GO.**

## Version-specific evidence

| Record | File | Published size | License shown |
| --- | --- | --- | --- |
| [Zenodo 23371775](https://zenodo.org/records/23371775), Oct 14, 2026 | iot_dataset_v7.zip (MD5 6b858e337a8241b89f4d76f9a1454a60) | 42,020,554 rows, 87 columns | Copyright nauss 2026 |
| [Mendeley j9xffc2psb/6](https://data.mendeley.com/datasets/j9xffc2psb/6), previous release | iot_dataset_complete.zip | 49,902,287 rows, 88 columns | CC BY 4.0 |

Copyright wording by itself is not a broad permission to reuse data. CC BY
for the **different previous v6 release** cannot automatically be asserted
for this Zenodo v7 archive. A description that lists possible research
applications is not a definitive license grant.

**Action required:** verify the exact v7 Mendeley file checksum plus its
version-specific reuse license, or seek written permission from a qualified
NAUSS rights holder identifying research/model benchmarking and publication
of aggregated results. Archive the reply or official rights notice. Do not
redistribute original records or claim this rights gate PASS in the meantime.
This is a cautious research compliance check, not legal advice.

Structured source review:
[P0_IOT_SFC_V2_LEGAL_SCHEMA_SOURCE_AUDIT.json](P0_IOT_SFC_V2_LEGAL_SCHEMA_SOURCE_AUDIT.json).

## Feature/schema mismatch risk

The existing V2 Zeek adapter requires exactly these flow keys:
ts, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto.
Missingness-aware optional columns: duration, orig_bytes, resp_bytes,
orig_pkts, resp_pkts, conn_state. Any aliases such as src_ip, dst_ip,
timestamp, protocol are suggestions only; none can be auto-mapped as proven
equivalent bidirectional connection flow telemetry.

The publisher says this file *mixes log types*. Reported dominant sources:
dns.log ~66.06%, conn.log ~28.01%, weird.log ~2.73% and MQTT publish logs.
Do not treat DNS/HTTP/application events as connection flows just because
they share a consolidated CSV header. Require verifiable row-level native
conn.log origin and sensor direction; never create absent counters as zeros.

## Safe local header-only preflight (no extracted 13.56 GB CSV)

The Drive connector cannot download 776.5 MB (256 MiB connector limit).
Thus the true CSV header has NOT yet been inspected in this session.

From a legitimate local copy of the ZIP, in Windows PowerShell inside
the cloned NetworkPulse-AI repository root (where networkpulse folder exists):

    py -m networkpulse.evaluation.iot_sfc_schema_audit --archive "C:\Users\YOUR_USER\Downloads\iot_dataset_v7.zip" --report "C:\Users\YOUR_USER\Downloads\networkpulse_iot_sfc_header_audit.json"

Send only the **small JSON report**, not raw CSV, ZIP, IP, UID, timestamps,
ground-truth labels, private data or secrets.

The script (i) SHA-256 and MD5 verifies the **whole original ZIP**,
(ii) checks one expected non-encrypted CSV member, and (iii) bounds
decompression/inspection to a single CSV header line <=131072 bytes.
It reads no CSV rows or label values; never runs, unpickles, tunes or tests
the model. ZIP-member CRC verification still requires the full uncompressed
13.56 GB member, so it is explicitly NOT CLAIMED.

Header-only checks are not proof of numeric mapping, source-log separation
or class-label correctness. Even a perfect 87-column header remains
**NOT APPROVED FOR SCORING** until separately verified row-level semantics,
independent ground truth and permitted use. This dataset is a controlled
laboratory, not an independently operated production SOC.

If true header names differ from native Zeek contract, build/review a
separate versioned adapter **before** inspecting any label values. Keep
the exact original baseline SHA and threshold unchanged.
