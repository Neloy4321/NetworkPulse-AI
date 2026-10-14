# Reproducible native-model training and candidate releases

This is the operational, operator-invoked training-to-candidate path, not a
research notebook or a synthetic benchmark. It stages a *candidate* that can
be reviewed and registered; it **never replaces** `MODEL_PATH`, starts a
runtime service, or automatically promotes anything into production.

## 1. Authorize and fingerprint the exact canonical dataset

The `train-release` command accepts canonical `FlowEvent` JSONL, with the
existing strict Pydantic schema including timezone-aware UTC timestamps,
binary labels and flow metadata. Source rows must already be in chronological
order. A one-line record may not exceed the parser's existing 1 MB limit.
A 250 MB file and an explicit row cap (default 20,000, maximum 100,000)
prevent accidental unbounded in-memory training. Exceeding caps **fails**,
not silently downsamples.

Compute and independently record a SHA-256 digest of the authorized data file
before training. The CLI requires its exact digest and refuses a changed file:

```bash
sha256sum /secure/approved/training-flows.jsonl
networkpulse train-release \
  --data /secure/approved/training-flows.jsonl \
  --dataset-sha256 "<paste-the-verified-sha256>" \
  --source-id "approved_capture_2026_10_14" \
  --name "native-20261014-v1" \
  --root /secure/candidates \
  --max-events 20000 \
  --min-gap-seconds 30 \
  --seed 42 \
  --quantile 0.97 \
  --min-f1 0.60 \
  --max-alert-fraction 0.15 \
  --max-fpr-upper-95 0.10 \
  --registry-root /secure/registry
```

*These thresholds are examples, not claims that any particular dataset or
model passes.* Choose and record the validation policy before training and
do not tune it against the test labels. The command will refuse the release
if the policy is unmet. The independent caller owns source authorization,
ground-truth review, time-contract review and retention approval; a SHA only
protects bytes **after** a reference digest has been obtained and authenticated.

## 2. Data quality / leakage gates

- The exact existing native `Detector.train` split is 60% / 15% / 25%
  chronological. The candidate pipeline validates UTC order, unique event
  identity, no cross-boundary timestamp equality, optional *minimum temporal
  gap*, one source contract, and complete binary labels. It checks at least
  50 benign fit events, 20 benign calibration events, and 20 benign + 5
  attack events in the later holdout.
- All records participate in training/splitting. The raw training file's
  source SHA and a SHA of ordered event identities are recorded for tracing.
  No raw IPs, UIDs, source rows or JWT tokens are exported to manifests.
- Labels are used for benign-only fit selection and labeled holdout metrics;
  the late holdout is not used to calibrate the score threshold.
  `F1`, alert fraction and optional 95% Wilson FPR upper bound gates
  are computed on the *internal, chronologically later* holdout.
- "Independent" requires separately audited real-world site and label
  provenance. Training on the UNSW-NB15 cyber range and reading internal
  holdout metrics does **not** meet that requirement.

## 3. Immutable model + manifest + registration

The release path `<root>/<candidate>/` contains `model.joblib` and
`manifest.json`. Candidate names are restricted; a duplicate name fails
rather than overwriting a model. Manifest includes raw source and event-key
fingerprints, feature version, seed/quantile, exact split counts/windows,
held-out metrics, policy gates, artifact SHA-256, and a functional
held-out-score fingerprint. The latter should match when fitting the
same events with the same seed and code even though artifact bytes may differ
because of training timestamps and environment differences.

```bash
networkpulse verify-release --directory /secure/candidates/native-20261014-v1
networkpulse model-registry status --root /secure/registry
```

Verification hashes the stored artifact **without unpickling it**.
Optional registration validates the release manifest and binds its lineage
fingerprint to the registry candidate record. Registration **does not make a
release active**. Promotion requires the already documented operator steps,
independent-site receipts and explicit production policy. The registry
remains single-node and local: protect filesystem permissions, serialize
operator actions, and distribute signed artifacts through an external
approved release system for multi-node production.

## 4. CI and recovery

The native real UNSW-NB15 workflow downloads the user-authorized SHA-pinned
archive into an ephemeral runner. It uses original raw earlier
`UNSW-NB15_1.csv` flows for both the existing detector and this candidate
release function, compares their predictions on later original capture,
verifies the artifact hash, registers an **inactive** candidate, and runs
the existing 800-flow authenticated API/SOC/MLOps replay. That training set
is an explicitly declared *bounded reservoir sample*, not a full raw capture
and not independently verified as a new site. The generated artifact,
source rows, private token keys, and registry are removed with the runner;
only aggregate evidence is archived.

If a release fails partway, the isolated candidate directory is deleted
and no production artifact is touched. Candidates are immutable; a retry
uses a new version name only after root-cause analysis. Operator backup and
rollback instructions remain in `MODEL_LIFECYCLE.md`. Do not mistake an
internal performance gate or checksum for independent production clearance.

## Known limits

This initial phase does not add automated self-training, source signing,
cross-site validation, distributed promotion, feature-store versioning or
a secure external provenance attestation authority. Promoting a model
remains an explicit human-controlled operation.


## Separate later-capture holdout — preferred for real deployments

For real captures, the *earlier* source may contain enough benign traffic for
fit and calibration but not both attack/benign classes in its internal final
quartile. Do **not** fabricate attacks or weaken the label gate. Instead pass
an independently reviewed, strictly **later** labeled canonical capture:

```bash
networkpulse train-release \
  --data /secure/approved/earlier-flows.jsonl \
  --dataset-sha256 "<pinned-SHA256-of-earlier-file>" \
  --source-id "site_a_earlier_2026" \
  --validation-data /secure/approved/later-flows.jsonl \
  --validation-sha256 "<pinned-SHA256-of-later-file>" \
  --validation-source-id "site_a_later_2026" \
  --name "native-site-a-v1" --root /secure/candidates \
  --min-gap-seconds 60 \
  --min-f1 0.60 --max-alert-fraction 0.15
```

The pipeline ensures the validation capture has **at least 20 labeled benign
and 5 labeled attack events**, no internal duplicate flow identities, strict
chronological order, *no overlap or time-embargo violation* with all earlier
training/calibration rows, and no repeated identities across captures.
Training/calibration occur **entirely before** the later capture is scored.
The candidate's release gates and registry metrics refer to this separate
later capture, while internal pre-validation diagnostics remain explicitly
separate in detector metadata. The manifest carries both source SHA-256
declarations and both input-identity fingerprints but no original IPs or
events. Captures from the same site or original cyber range are **not**
independent-site validation; this must be audited outside the application.

CI enforces this exact production path using original raw earlier
`UNSW-NB15_1.csv` and later `UNSW-NB15_4.csv` samples (SHA-pinned original
archive, bounded deterministic reservoir per capture). No real sample is
silently relabeled, augmented or treated as an entire unselected archive.
