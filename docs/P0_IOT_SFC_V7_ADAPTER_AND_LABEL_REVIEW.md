# IoT-SFC v7 strict FlowV2 adapter: eligibility and label provenance rules

## Objective and scope
This phase implements **source-specific adapter code** without consuming original IoT-SFC
CSV record values, calibrating threshold, fitting a model, or passing the target through
the original frozen model. The original baseline SHA256 remains
`cd239783fd4318c0c4e897f1d451c2d5af4b42132979c79a4e489df626f538a5`;
its threshold remains **0.20**. ML research/operational acceptance is **NO-GO**.

Exact original Zenodo v7 archive SHA256:
`070b1356e5bd296e584109fae79139cfe0f20ff4790f69e42994d67362cb9f62`.
See [actual 87-column pinned header](P0_IOT_SFC_V2_VERIFIED_HEADER_EVIDENCE.json).

## Defined (synthetically tested) adapter behavior
- Recognize only **explicit** `log_type == "conn.log"` source records. Reject
  `dns.log`, `http.log`, `mqtt_publish.log`, `weird.log`, missing and
  ambiguous source types: no conversions from application events to flows.
- Explicitly map `orig_h -> id.orig_h`, `orig_p -> id.orig_p`,
  `resp_h -> id.resp_h`, `resp_p -> id.resp_p`.
  The source type is `zeek` in the existing immutable V2 feature contract.
  Never invent reverse direction, zero-impute absent counters or rewrite model weights.
- Keep `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts`, `duration`
  genuinely missing (None) when source has no measurement. Reject malformed
  IP, port, timestamp, negative, fractional count or invalid sensor fields.
- The adapter returns a **label-free FlowV2 candidate**; producer's `attack`,
  `type_of_attack`, `label_source`, `window_id`, IPs, UIDs or timestamps
  are not exposed as ML model features. Numeric feature parity with the
  original native Zeek adapter is tested on invented synthetic examples.
- A separate producer-label inspector recognizes only literal binary
  `0`/`1` and requires attack family/source/window metadata for malicious
  rows. Its output **always marks producer labels independently unreviewed**
  and does not certify ground truth. No human approval is manufactured.

## Gates before original 42M-row reading or model scoring
1. **Permission:** screenshot of the "cite all versions" DOI banner is citation
   guidance, not a license. Zenodo current v7 displays "Copyright nauss 2026";
   older Mendeley v6 displays CC BY 4.0. Require v7-specific rights for intended
   reuse / written permission; keep original record and license in evidence.
2. **Original flow source contract:** independently confirm actual values of
   `log_type`, true Zeek origin/direction, canonical numeric semantics, timezone,
   authenticated raw `conn.log` equality, and authentic row coverage. If the
   producer uses different source-log vocabulary, record this and review a
   separately pinned adapter version rather than silently matching substrings.
3. **Ground truth:** original session schedule versus `window_id`/`label_source`,
   time-boundary checks, attack direction/flow association, benign adjudication,
   reviewer signoff, and per-day class support. A timestamp window alone cannot
   establish an independent verified malicious flow.
4. **Leakage control:** full source training fingerprints and capture family/site
   independence, duplicates, feature-vector parity, event day groups.
5. **One predeclared frozen target evaluation:** FPR Wilson upper95 <= 5%,
   recall Wilson lower95 >= 80%, >=200 real benign, >=100 real attack,
   >=3 capture days and corroborating per-day/cluster-aware uncertainty. No
   target-guided threshold tuning or model selection.
6. **Operational gates separately:** independently operated field network,
   separate human sign-off, trusted Ed25519 release, real TLS/OIDC staging,
   live sensor parity/alert workload. Public lab benchmark is not enough.

## Tests
`python -m pytest -q tests/test_iot_sfc_v7_conn_adapter.py`.
All tests are synthetic; no new model is fitted or evaluated. Existing
production IsolationForest, drafts #25 and #26 and default service unchanged.
