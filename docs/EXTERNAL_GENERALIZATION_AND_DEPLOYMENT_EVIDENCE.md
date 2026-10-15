# NetworkPulse-AI: frozen-model generalization and private-staging evidence

## Scope and truthfulness

This patch implements production-oriented **acceptance gates**, not a claim that the
existing Isolation Forest already generalizes across networks. No independent
CIC-IDS2017/ToN-IoT/production-site holdout has been supplied or evaluated in this
package. Synthetic test fixtures only exercise guardrails. The user must run
these commands with authorized, independently labeled, real network-flow data,
a trusted approved model and permitted isolated staging infrastructure.

Machine-learning metric correctness, cryptographic provenance, traffic-sensor
behavior, false-positive burden, and real-site operational readiness are different
claims. Neither a 100%-successful Redis unit test nor a high within-UNSW score
proves generalization to another site.

## Required data and preflight

1. Choose a *frozen, signed and registry-approved* native `Detector` model. Do
   **not** train or calibrate on the external test corpus; its threshold must
   have been fixed from pre-existing development/calibration data.
2. Record original training-domain corpus SHA-256, model artifact SHA-256 and a
   separate **independent, externally labeled** holdout corpus SHA-256. The
   original training corpus must be reproducible. Reconstructing a different
   train set after the fact does not prove nonoverlap.
3. Flow records must be canonical `FlowEvent` JSONL with `label` equal to
   `benign` or `anomaly`; input validation still uses the repository's strict
   `networkpulse.adapters.iter_jsonl`. Plain Zeek/Suricata logs usually do not
   provide independent per-flow attack labels; they are NOT sufficient for
   supervised false-positive measurement without audited annotations.
4. Include multiple genuine capture days and both classes. Existing project
   training/event identifiers are never exposed in the public evaluation
   evidence; ledger output is private mode 0600. Cross-adapter normalized flow
   fingerprint matching detects many duplicate captures re-exported with a
   different UID or source name. It cannot prove no overlap when timestamps,
   addresses or counters are altered.
5. Choose and REVIEW acceptance thresholds **before** looking at test labels or
   scores. For example, 2% maximum FPR and 90% minimum TPR are illustrative
   contract values, not site-approved defaults or achieved measurements.

Example pre-registered `private/external-holdout-spec.json`:

```json
{
  "train_domain": "UNSW-NB15",
  "holdout_domain": "independent-authorized-site-B",
  "training_sha256": "<64-lowercase-hex-of-training-corpus>",
  "holdout_sha256": "<64-lowercase-hex-of-original-holdout>",
  "model_sha256": "<64-lowercase-hex-of-approved-model>",
  "acquisition_statement": "Authorized site B sensor collection, independently acquired",
  "label_provenance": "Independent analyst labels, adjudication procedure recorded",
  "independent_capture_attested": true,
  "max_false_positive_rate": 0.02,
  "min_true_positive_rate": 0.90,
  "min_benign": 1000,
  "min_attack": 100,
  "min_capture_days": 3,
  "max_rows": 50000
}
```

The strings describe operator assertions, not cryptographic proof of
acquisition independence. The signed model registry remains the existing
project production release authority; there is deliberately no unsigned
`Detector.load()` fallback in the CLI.

### Step 1: Generate training overlap ledger

```bash
python -m tools.export_training_id_ledger \
  --original-training-corpus /private/original-train.jsonl \
  --source-sha256 '<training-corpus-sha256>' \
  --output /private/evidence/original-training-ledger.tsv
sha256sum /private/evidence/original-training-ledger.tsv
```

The TSV holds exactly two hashed fields per event: canonical 32-hex event ID
and a 64-hex, source/UID/label-independent flow fingerprint. The underlying
IP addresses, packet counters and event JSON are not present as plaintext.
The ledger is sensitive (some metadata may be guessable): keep it restricted,
never commit it to public GitHub, and do not replace it with synthetic IDs.

### Step 2: Evaluate approved frozen model on independent holdout

```bash
python -m tools.run_frozen_external_holdout \
  --holdout /private/site-b-labeled.jsonl \
  --spec /private/external-holdout-spec.json \
  --model /secure/approved-model.joblib \
  --registry-root /secure/approved-registry \
  --training-event-ids /private/evidence/original-training-ledger.tsv \
  --training-event-ids-sha256 '<ledger-sha256>' \
  --report /private/evidence/site-b-external-evaluation.json
```

The evaluation:

- Scores the **unchanged** approved model, without training/SMOTE/threshold
  adjustment, and refuses corrupt or SHA-mismatched model bytes **before**
  loading joblib/pickle.
- Requires complete benign/anomaly labels, distinct train/test domain names,
  different train/holdout SHA-256, unique canonical event IDs and zero overlap
  against both training-ledger hashes.
- Reports confusion matrix, FPR, recall, precision, F1, average precision
  (PR-AUC AP), 95% Wilson bounds and per-day false-positive/recall rates.
- Accepts only if pre-registered counts, capture-day support, **upper** 95%
  Wilson FPR bound, **lower** 95% Wilson recall bound, and every day's FPR
  check pass. Otherwise exit code 2 and `status=failed`.
- Uses a bounded maximum of 250,000 labeled records, aggregation-only JSON,
  owner-only (0600), fsynced evidence and no replacement of prior reports.

Caution: network flows are correlated. Wilson intervals are useful diagnostics
but may be too narrow. For a production sign-off, add independently acquired
site/day-grouped replications and cluster-bootstrap confidence intervals; the
current gate checks minimum benign-covered days but does **not** implement
cluster bootstrap. Also separately review the deployment-relevant alert burden
and hours with benign-only traffic. A passing holdout is **not** field readiness.

### Step 3: Execute approved actual staging data campaign

Follow the repository's `docs/STAGING_LOAD_VALIDATION.md`, using the **same
approved model SHA-256** and original holdout corpus SHA-256. The staging
acceptance JSON must show `status=passed`, complete Redis ACK and PostgreSQL
new-row reconciliation, no remaining pending/DLQ, and configured latency and
throughput threshold success. A synthetic `networkpulse.container_failover`
CI report alone does **not** satisfy this site evidence requirement.

### Step 4: Independently sign and link the evidence

Create an out-of-band, trusted Ed25519 public key for the authorized staging
operator. **Do not commit the private key or expose it through CI logs.** The
operator reviews the actual staging run and only then signs the canonical JSON
attestation (`sort_keys=true`, compact separators, UTF-8, `ensure_ascii=false`).
The detached signature is standard Base64 encoding of Ed25519 over these exact
canonical bytes. The public key PEM is distributed out of band and pinned by
security operations. Use the offline operator signer below; private PEM files
must be owner-only (mode 0600) and must never enter GitHub Actions.

```bash
python -m tools.sign_staging_attestation \
  --attestation /private/evidence/site-attestation.json \
  --private-key /secure/offline/operator-private.pem \
  --signature /private/evidence/site-attestation.sig
```

Example attestation fields (SHA digests must come from the actual files):

```json
{
  "schema_version": 1,
  "environment": "isolated_staging",
  "sensor_capture_operator_attested": true,
  "approved_staging_execution_attested": true,
  "model_sha256": "<approved-model-sha256>",
  "external_report_sha256": "<sha256-of-external-report-json>",
  "staging_report_sha256": "<sha256-of-staging-report-json>",
  "operator_identity": "approved-independent-operator",
  "staging_capture_reference": "approved-site-ticket-number",
  "review_timestamp_utc": "2026-10-15T10:00:00+00:00",
  "topology": "single_node"
}
```

Run the verification (this does not sign the attestation itself):

```bash
python -m tools.verify_deployment_evidence \
  --external-report /private/evidence/site-b-external-evaluation.json \
  --staging-report /private/evidence/site-b-staging-load.json \
  --operator-attestation /private/evidence/site-attestation.json \
  --detached-signature /private/evidence/site-attestation.sig \
  --trusted-public-key /secure/trusted-operator-pub.pem \
  --report /private/evidence/site-b-linked-evidence.json
```

The verifier checks SHA256 fingerprints, the Ed25519 signature, source/model
identity, unique event counts, FPR/recall gate status, Redis/SQL reconciliation
and staging latency/throughput thresholds. It reports **only**
`integrity_passed_independent_site_review_required` when successful and
`production_certified=false`. It cannot independently prove the assertions in
the signed operator statement or that CI ran on site. Multi-node HA failover,
site RPO/RTO, end-to-end alert latency, production traffic baseline, long soak
and change-control approval are separate pending requirements.

## Technical integration

Copy `networkpulse/*.py`, `tools/*.py`, `tests/*.py` from the patch over the
corresponding **new paths** in a current and freshly inspected repo, keeping
existing files untouched. The project's current `quality.yml` pytest discovery
should collect the new unit tests. Do **not** claim merge, current GitHub CI
success, field FPR or published deployment evidence until those steps actually
complete on the exact new revision and approved infrastructure.
