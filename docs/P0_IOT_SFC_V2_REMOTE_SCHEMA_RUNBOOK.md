# P0 IoT-SFC v2 official-source ZIP: isolated, header-only acquisition

## Why this job exists
The user's Google Drive copy of `iot_dataset_v7.zip` is 776,500,807 bytes.
The connected Drive download API rejects files over 256 MiB. Do not require
the user to unpack 13.56 GB, expose sensitive traffic, or resend files merely
to learn the actual header shape.

This workflow uses the official public Zenodo record's file endpoint directly
on a disposable GitHub Actions runner. It checks exact byte length and
**previously preregistered** SHA256
`070b1356e5bd296e584109fae79139cfe0f20ff4790f69e42994d67362cb9f62`
*before* ever attempting ZIP header extraction. Any failed download, mismatch,
unsafe archive, invalid header or network error stops the job (not a PASS).

**Model and threshold stay untouched:** unsigned baseline SHA256
`cd239783fd4318c0c4e897f1d451c2d5af4b42132979c79a4e489df626f538a5`,
cutoff **0.20**. The 13.56 GB member `iot_dataset_v7.csv` is NOT extracted.
The reader opens at most 131,073 bytes of a **single CSV header line**; it
reads no data records, label values or prediction targets, and does not
deserialize the RF model. All raw original ZIP bytes are deleted in an
`if: always()` step; only the small aggregate header JSON is uploaded with
14-day retention.

## Evidence interpretation
This is a **technical feasibility probe**, not a usage-license approval or
acceptance benchmark. The public Zenodo v7 shows "Copyright nauss 2026";
Mendeley v6 showed CC BY 4.0 but is a DIFFERENT file/row count. Do not
auto-grant v7 re-use rights from v6. Row-level label provenance, connection
source separation and independence are not established by column names.

The existing V2 adapter only accepts verified Zeek `conn.log` flow semantics;
IoT-SFC is a mixture of DNS, connection, HTTP, MQTT and other event types.
The header checker always leaves `accepted_for_model_scoring=false`.
Even if all expected fields occur, a separate independently reviewed adapter,
row provenance, labels, source overlap and legal use must pass before any
model score is produced. A laboratory-only score can never certify the
independent field-site, signed real service and operator required for full P0.

## Where to find results
- Workflow: `.github/workflows/p0-iot-sfc-source-header.yml`.
- Trigger on PR changes to this workflow/runbook, or dispatch from default branch
  after merging.
- If an output JSON exists, download the private workflow artifact
  `iot-sfc-v7-official-sha-pinned-header-only-no-labels` and inspect
  `schema.required_zeek_conn_missing`,
  `schema.possible_unverified_aliases`,
  `schema.possible_log_source_columns`, and
  `schema.header_only_schema_status`.
- A failed download does **not** authorize switching silently to
  unrelated archives or lower checksum gates. Alternate acquisition must use
  the identical preregistered source SHA and be explicitly documented.
- Never publish original ZIP, CSV, flow records, IPs, IDs, raw request logs,
  ground truth or model pickle artifacts in GitHub.

## Scope
Zero model, threshold, feature contract, production API, Docker deployment,
original CI quality, or unfinished ML draft PR #25/#26 modifications.
ML P0 remains **NO_GO** until actual fresh quality evidence and independent
field-site/real operator requirements exist.
