# P0 Model Freeze and Prospective External Evaluation — operator handoff

**Status: RESEARCH FREEZE / RELEASE NO-GO.**
No product promotion, signed active model, independent physical site, fresh
operationally adjudicated labels or verified deployment evidence is claimed.

## Candidate provenance and manual source-only selection

Stage 3 discovered FPR upper confidence-bound failures when trained only on
UNSW capture 1 and tested on 2/3/4. Four-fold Leave-One-Capture-Out Stage 4
trained on three already-exposed raw UNSW parts, scored the fourth, and
reported benign FPR 0.83%–2.54% for RF v1 and 0.85%–2.52% for the
port-bucket/no-state RF. **Neither is independent-site acceptance**, because
all source parts come from the same cyber range and most folds share host pairs.

For the **next research-only frozen candidate**, we explicitly select
`rf_supervised_port_buckets_no_state` on qualitative sensor-compatibility
grounds: it avoids interpreting the UNSW `state` categories as Zeek states
and avoids imposing ordinal distance on numeric destination ports.
This selection is **made after seeing exposed source development results**;
it is a documented exploratory model choice, not proof that this candidate
outperforms others outside UNSW.

The fixed freezing recipe uses only these four previously exposed UNSW
CSV members from the SHA-pinned R2 ZIP
`3c7500f120405b21b44a2bf05134f49491f88a655ae3091fc1b269c4c9ece79a`:
each uniform sample has 6,000 records with seeds 60, 61, 62 and 63.
Deduplicate both canonical IDs and source-independent normalized flow
fingerprints, then fit **one** fixed 160-tree `RandomForestClassifier`,
`max_depth=12`, `min_samples_leaf=10`,
`class_weight="balanced_subsample"`, `random_state=42`,
fixed binary probability cutoff **0.5**, and a fit-only `DictVectorizer`.

No external target data, TON flow labels, or deployed IsolationForest
weights are used to make this research bundle. Every source capture has
already been inspected, so the final source fit has **no pristine UNSW
holdout left**. The study is not a site/day statistical acceptance study.

## Exact CI outputs

The source-only workflow checks:
- Approved R2 source length and full ZIP SHA before reading CSV records
- Stage 1–4 provenance, labels, false-alarm reporting, held-out fold integrity
- Frozen bundle serialization and same-input prediction round-trip equality
- Model digest recorded in a **research-only unsigned manifest**
- A mode-0600 TSV ledger of canonical training flow IDs and
  adapter-independent normalized-flow fingerprints; verifies its SHA-256
  against the frozen manifest. The restricted ledger is **not uploaded**.
- Reconstruction of that ledger from the exact same source ZIP; raises an
  error if byte-for-byte ledger hashes differ
- Same CI enforces `production_approved=false`,
  `independent_site_evaluated=false`, and no nonexistent operator signature

A successful workflow may provide **two separate artifacts**:
`source-only-feature-audit-research-only` (aggregate JSON reports +
frozen source manifest) and
`unsigned-frozen-source-rf-research-only` (binary research model).
The latter is retained by GitHub Actions for **30 days**; it is NOT
a permanent immutable release registry. Preserve it through an
operator-approved private artifact registry and externally pin its exact
SHA-256 **before** prospective scoring. Its source weights are trained
on a research dataset, never a signed production model.

**Security:** SHA-256 verifies bytes but is not a signature. Joblib uses
pickle: NEVER execute or `joblib.load` untrusted models. The external
scorer pins the complete bundle SHA to an out-of-band reviewed value first.
A proper signed promotion still requires the project's existing
Ed25519 release-approval mechanism, human approval and deployment evidence.
The current `Detector.load` cannot ingest this RF research bundle.

## Private training ledger reconstruction (only in approved compute)

This ledger contains hashes derived from network identifiers: treat it as
**sensitive data**. Do not publish, commit or attach it to public Actions.

```bash
python -m networkpulse.evaluation.source_training_ledger \
  --unsw-zip /secure/unsw-source.zip \
  --frozen-manifest /secure/frozen-source-rf-manifest.json \
  --private-output /secure/original-training-ledger.tsv
```

It fails unless the exact source archive SHA, sampling choices, dedup counts
and final TSV checksum all match the frozen manifest. The output is
mode 0600 on POSIX. Keep the ledger restricted for an actual external
evaluation. Existing native training-identity tooling in
`networkpulse.generalization_evidence` provides the same two-field
ledger format.

## External research scoring — not yet run on a new dataset

Prerequisites:
- A **new untouched** authorized genuine labeled flow corpus, converted
  by an independently verified *lossless* native Zeek/Suricata/canonical
  adapter into strict `FlowEvent` JSONL. Missing byte/packet counters,
  connection states and timestamps must not be made up.
- Independently adjudicated `benign` and `anomaly` labels; a Suricata
  rule alert or Zeek connection alone does not provide ground truth.
- Prospectively recorded exact 64-char SHA-256 of the labeled canonical
  JSONL, frozen model SHA-256, dataset/sensor contract, authorization reference
  and review process **before** inspecting target labels.
- The restricted, SHA-matching training-flow ledger above. Any normalized
  train/test flow overlap, malformed flow, missing label, invalid digest
  or repeated holdout flow causes **FAIL CLOSED**.
- Sufficient unaltered class support (at least 200 benign and 100 attack
  labels) for a *research-only* numeric evaluation. Real site/day replication,
  reviewer and false-alert-volume acceptance require more than these floors.

Private source attestation (operator must replace example values with real
evidence; strings are claims, **not independently verified attestations**):

```json
{
  "schema_version": 1,
  "dataset_family": "a-new-authorized-collection-not-UNSW-or-TON",
  "source_operator": "authorized-network-operator",
  "authorization_reference": "private-written-consent-reference",
  "label_review_method": "separate-human-analyst-adjudication",
  "native_sensor_contract": "documented-zeek-or-suricata-to-canonical-mapping",
  "site_provenance_kind": "independent_operator_attested",
  "capture_period_utc": "approved-UTC-date-range",
  "pre_registration_reference": "frozen-study-protocol-ID",
  "canonical_jsonl_sha256": "REPLACE_WITH_FULL_REAL_TARGET_SHA256",
  "labels_are_independently_adjudicated": true,
  "reviewer_confirmed_frozen_model_before_target": true
}
```

Run locally on approved data **only after** freezing and obtaining
the restricted original training ledger:

```bash
python -m networkpulse.evaluation.prospective_external_rf \
  --bundle /secure/frozen-source-rf-research-only.joblib \
  --manifest /secure/frozen-source-rf-manifest.json \
  --expected-bundle-sha256 '<EXACT_REVIEWED_MODEL_SHA256>' \
  --private-training-ledger /secure/original-training-ledger.tsv \
  --labeled-canonical-jsonl /secure/new-external-labeled.jsonl \
  --expected-target-sha256 '<EXACT_REVIEWED_TARGET_SHA256>' \
  --source-attestation /secure/source-attestation.json \
  --output /secure/research-external-evaluation.json
```

The scorer computes confusion matrix, FPR, recall, Wilson intervals,
per-day counts, exact source overlap detection, and an explicit **research
numeric gate** at FPR upper ≤5% and recall lower ≥80%. It ALWAYS reports
`operational_ml_acceptance_demonstrated=false`,
`production_deployment_verified=false` and
`active_signed_artifact_equivalence_verified=false`: a JSON source
attestation cannot cryptographically establish a site's independence or
legitimacy. The code cannot force one-shot dataset disclosure across all
computers; a trusted independent operator must govern dataset custody
and prevent repeated target-driven tuning.

## Remaining true P0 acceptance blockers

1. Human-reviewed active **production-compatible** candidate packaging:
   implement explicitly versioned RF runtime scoring, signed/revocable
   release, registry compatibility, and forbid unintended fallback.
2. Controlled actual deployment with the **identical verified signed
   model**, origin/sensor schema contract, external secret management,
   live scoring parity, alert rates, site/day-grouped workload support,
   operational SLOs and independent human review.
3. Genuinely new independently operated site data and audited labels.
   A separate **IoT-23** capture from the Stratosphere Lab may test a
   second dataset *family* under research rules, but does NOT constitute
   a production network/site. Official source:
   https://www.stratosphereips.org/datasets-iot23
4. Rotate earlier-exposed R2 credentials and use a separate read-only
   bucket-scoped CI token. Do not embed any R2 secrets in artifacts.

Until all those requirements are independently satisfied,
**P0 Operational ML Acceptance remains NO-GO.**
