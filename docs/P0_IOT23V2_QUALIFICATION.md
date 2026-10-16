# P0 ML: prospective IoT-23v2 research capture qualification

**Status: schema adapter engineering complete; real IoT-23v2 data NOT evaluated.**
NO CLAIM of independent production-site acceptance or improved FPR.

## Download exactly one public scenario

- Scenario: `CTU-IoT-Malware-Capture-34-1` (Mirai, Dec 21, 2018).
- Version: **IoT-23v2**, whose labeled Zeek flow files have improved
  annotation organization compared with the original IoT-23 release.
- Authoritative scenario directory:
  https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-34-1/
- The direct ~2.9 MB `2018-12-21-15-50-14-192.168.1.195-zeek-conn-log.labeled`
  is linked within that official directory. It contains Zeek `conn.log`-style
  tab-separated rows with a compound `tunnel_parents   label   detailed-label`
  trailing field and benign/malicious tags.
- Do not download malware binaries or PCAPs for this study. One labeled flow
  file and the official README/labels.config are sufficient for initial
  native schema assessment. Keep raw IPs and UIDs private.

Stratosphere Laboratory's general dataset FAQ says citation is sufficient
for research use:
https://www.stratosphereips.org/datasets-faq

However the **older original-version individual-capture README** contains
an authorization instruction:
https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-34-1/

These source statements conflict. This plan uses the publicly listed **v2**
research data with citation but does **not** interpret the FAQ as a license
for unrelated redistribution/commercial production operation. Confirm the
terms with the provider if that broader use becomes necessary.

Citation:
Garcia, S., Parmisano, A., & Erquiaga, M. J. (2020).
*IoT-23: A labeled dataset with malicious and benign IoT network traffic.*
Zenodo. https://doi.org/10.5281/zenodo.4743746

## What the adapter does

`networkpulse/evaluation/iot23v2_source_adapter.py` implements a
**strict schema-only preprocessing contract**, not model tuning.

1. Verify the exact official Zeek tab-separated `#fields` header. Reject
   format changes, unknown labels, malformed UTF-8 and inconsistent rows.
2. Preserve source timestamps, addresses, ports, protocol, counters,
   connection-state fields and the original binary benign/malicious label.
3. Reject/record incomplete duration, byte or packet counts rather than
   fabricating zeros or using incompatible IP-layer counters as
   application-payload counters.
4. Require at least 200 natural complete benign and 100 natural complete
   attack examples, but report the **complete-case exclusion fraction**:
   excluding large/missingness-skewed portions of a capture cannot prove
   representative detection performance.
5. Write raw canonical labeled JSONL ONLY to a private destination; publish
   a separate metadata-only SHA-256/integrity/record-count report, no IPs.
6. Keep threshold and frozen source-trained RandomForest model unchanged.
   If any real prospective study proceeds, pin source/canonical SHA-256
   first, reconstruct restricted UNSW training-flow ledger and reject
   any flow overlap. The *official* labels are researcher rule-assisted,
   not independently audited production incident adjudications.

Synthetic-only CI is separately defined in
`.github/workflows/iot23v2-schema-preflight.yml`, which requires NO
model artifacts, network dataset or R2 access. Passing this CI indicates
the parser works on fixtures, not that the model performs on IoT-23.

## Evaluation and acceptance limits

A frozen RF source model exists from previous UNSW-only research with
SHA `ba5fbc2cb171b0f79a31d99e71fbe438135325babc9d939d26c8589f66ff954b`.
IoT-23v2 would be a **different laboratory-family external research test**,
not a physically independent production SOC/network. The original
two-class study targets (95% Wilson benign FPR upper <=0.05 and attack
recall lower >=0.80) must never be reduced merely to obtain green CI.

**No production P0 Operational ML Acceptance without independently
verified field provenance, full unmodified signed/active model runtime,
alert burden, operational SLOs and independent adjudication.** Public lab
benchmarks cannot fill those absent pieces by assertion.
