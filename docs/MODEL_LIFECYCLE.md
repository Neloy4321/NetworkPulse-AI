# Local model registry, shadow testing and rollback

This is an **operator-controlled, trusted-file** local registry. It does **not** load uploaded/untrusted pickle artifacts. Do not claim model security certification or production-validated attack detection.

1. `networkpulse bootstrap` and `networkpulse generate-demo ...` as described in README.
2. `networkpulse model-registry register --name baseline-1 --file data/model.joblib --min-f1 0.7 --max-alert-fraction 0.3`
3. `networkpulse model-registry status`
4. Train a candidate against **authorized** data when available; while waiting, `networkpulse train --data examples/generated-demo.jsonl --model data/candidate.joblib --seed 29` uses only synthetic flows.
5. `networkpulse model-registry register --name candidate-2 --file data/candidate.joblib --min-f1 0.7 --max-alert-fraction 0.3`
6. `networkpulse model-registry shadow --name candidate-2 --active data/model.joblib` compares outputs on deterministic **synthetic** flows. This command is not real online shadow traffic.
7. Stop API/workers, back up `data/model.joblib` and the database, then promote explicitly: `networkpulse model-registry promote --name candidate-2 --active data/model.joblib`. Restart all processes to reload the model.
8. To revert, stop all processes and run `networkpulse model-registry rollback --active data/model.joblib`, then restart.

Immutable registered candidates have SHA-256 checksums verified before promotion. Promotion is atomic per local filesystem (`os.replace`). Manifest and artifact are not cryptographically signed; registry operations must be restricted to trusted operators. Concurrency and distributed registry coordination are **not** supported; use an artifact service with signed releases for multi-node deployment.

**Promote gate limitations:** F1 and alert budget gates are computed only from model metadata, which can represent seeded synthetic tests. These gates do not independently certify training-set provenance or real-world generalization. Strict external-model promotion policy is still an operator responsibility.

## Reliability gates (October 2026)

The detector stores three **different kinds of evidence** separately:

- Benign calibration quantile diagnostics: descriptive distribution of the
  benign-only calibration scores. It is **not a guarantee** of future FPR.
- Chronological internal labeled holdout: confusion matrix, benign count,
  observed false-positive rate, one-sided 95% Wilson FPR upper bound, and
  protocol/sensor/port-class slices. Slices with fewer than 20 labeled benign
  observations withhold unstable FPR estimates. This does not verify new-site
  performance or independence of correlated flows.
- Model score *sensitivity*, optionally on at most 25 trusted canonical
  events: replaces **one numeric feature at a time** with its median from
  benign training and reports how the Isolation Forest score changes. It is
  **NOT SHAP, a probability, a causal explanation or attack attribution**.
  Optional original-model median metadata is only available for newly trained
  models. An older model requires a trusted local retraining for this command.

A new trusted model can be inspected without sending the original flows to
GitHub:

```shell
networkpulse explain-model --model data/model.joblib --data data/authorized-flows.jsonl --max-events 20 --output reports/score-sensitivity.json
networkpulse drift-report --model data/model.joblib --data data/authorized-flows.jsonl
```

The drift report now enforces at least **30 events**, checks PSI thresholds and
reference feature count and, when all rows have independent ground-truth labels,
includes **retrospective** FPR with uncertainty. Alert rates, PSI changes and
human descriptions are **not automatically equivalent** to intrusion evidence.

### Optional FPR gate when registering models

```shell
networkpulse model-registry register --name validated-candidate --file data/trusted-candidate.joblib --min-f1 0.7 --max-alert-fraction 0.15 --max-fpr-upper-95 0.05
```

This optional gate requires at least 100 internal held-out **benign** flows
and a one-sided Wilson upper 95% FPR bound at or below the supplied limit.
Internal holdout metrics can be optimistic if events are correlated or from the
same site. The command rejects any old artifact with missing FPR evidence.

### Signed production release gate — no unsigned self-approval

The production path now **requires a cryptographically verified Ed25519
signature**, verified against a locally mounted, security-admin provisioned
public-key trust store. Merely placing `independent_site_verified: true` in
unsigned JSON will fail. The configured trusted key is external to the
candidate release and must never be obtained from an untrusted model bundle.

**1. Independent security reviewer provisions signing trust outside Git.**
Generate/manage an Ed25519 key through an approved organization process
(prefer an HSM/offline workstation). The private key **must never enter** API
containers, Docker volumes, CI artifacts, logs or this repository. Provision
a read-only trust store at `/etc/networkpulse/release-trust.json`:

```json
{
  "schema_version": 1,
  "keys": [
    {
      "key_id": "approved-security-reviewer-2026",
      "enabled": true,
      "ed25519_public_key_base64": "<base64-of-raw-32-byte-public-key>"
    }
  ]
}
```

Changing `enabled` to false revokes new release approvals from that key.
Trust-store ownership, reviewer authority and key lifecycle must be independently
controlled; a signature does not establish that a validation claim is factually
correct.

**2. Independently review real labeled validation and prepare exact signed
change instructions** (no raw IPs in the approval). For example, prepare
`review-payload.json` with the *actual* SHA, previous release and metrics:

```json
{
  "candidate_sha256": "<registered-candidate-sha256>",
  "previous_active": "approved-previous-release",
  "operation": "promote",
  "change_id": "soc-review-ticket-20261014-001",
  "issued_at_utc": "2026-10-14T10:00:00Z",
  "expires_at_utc": "2026-10-15T10:00:00Z",
  "independent_site_verified": true,
  "live_sensor_contract_verified": true,
  "training_test_leakage_audited": true,
  "approved_by": "Authenticated security reviewer",
  "evaluation": {
    "benign_count": 1000,
    "attack_count": 100,
    "false_positives": 3
  }
}
```

For initial registration `previous_active` must be `null` rather than a
name. `operation` must be `promote` or `rollback` and the `change_id`
must be unique across successful production changes. Approvals expire and are
valid for at most seven days; signing a longer-lived approval fails closed.
The CLI verifies the real computed Wilson 95% upper false-positive bound
and requires at least 200 benign and 30 attack observations. The example
counts and dates are **not** a real signed approval or validation evidence.

**3. Sign offline (never inside the production container):**

```bash
python tools/sign_release_approval.py \
  --payload /secure/review-payload.json \
  --private-key /secure/ed25519-reviewer-private.pem \
  --key-id approved-security-reviewer-2026 \
  --output /secure/approved-release-envelope.json
```

The signing utility uses canonical JSON encoding (UTF-8,
`sort_keys=True`, `ensure_ascii=False`, compact separators, no NaN).
The resulting envelope includes `schema_version`, `key_id`,
`payload`, and base64-encoded `signature`. The operator receives only the
signed envelope, not the private key.

**4. Quiesce API/Redis workers, use a verified DB snapshot and approved
maintenance window.** Promotion is a single-node, POSIX-flock-serialized
operation, not a distributed rollout:

```bash
networkpulse model-registry promote \
  --production --name reviewed-model-v2 \
  --root /secure/registry --active /secure/data/model.joblib \
  --trust-store /etc/networkpulse/release-trust.json \
  --evidence /secure/approved-release-envelope.json \
  --max-fpr-upper-95 0.05

networkpulse model-registry verify-active \
  --root /secure/registry --active /secure/data/model.joblib
# Update MODEL_SHA256 to match the verified active SHA and restart ALL
# API and streaming/MLOps worker containers together.
```

An existing deployed model must already match the registry's active checksum.
An unregistered preexisting deployment cannot be silently overwritten. After
promotion, a journal and backup ensure a registry-write error restores the
previous artifact; an abrupt crash leaves a journal and **blocks further
mutations** until explicitly reconciled.

**5. Rollback requires a NEW, independently signed change** with
`operation=rollback`, `previous_active` set to the current candidate,
`candidate_sha256` referring to the approved older candidate, and a new
`change_id`. Run `model-registry rollback --production` with the new
envelope, trust store, root and active path. A second immediate rollback is
blocked (no automatic ping-pong). Stop/restart all scoring processes around
each change and update `MODEL_SHA256` before they restart.

**6. Recover interrupted local release operations** only after operator review:

```bash
networkpulse model-registry recover-interrupted \
  --root /secure/registry --active /secure/data/model.joblib \
  --expected-sha256 '<TARGET-SHA256-IN-REVIEWED-JOURNAL>' --confirm
networkpulse model-registry verify-active \
  --root /secure/registry --active /secure/data/model.joblib
```

If catalog+active bytes show a completed write, the recovery command retains
the new candidate and clears the stale journal. If the catalog remains at the
previous candidate, it restores the previous verified artifact and clears the
journal. Unexpected bytes, wrong destination, missing rollback backup or bad
checksum leave the journal intact for **manual incident handling**. A recovery
command never invents an approval or automatically changes a catalog record.
Do not run recovery concurrently with deployed live workers.

**Boundaries:** signature verifies the listed review key and immutable
change payload, not claim truth, independent site provenance, real IdP or
live deployment safety. The registry remains local and POSIX
single-filesystem: use external attested artifact distribution, HSM-backed
review, p95/p99 field validation, health-based controlled rollout, on-call
approval and monitoring for a real multi-node production deployment.



## Operational drift and lineage evidence — revision 0005

Unlike the offline `drift-report` command, the `mlops-monitor` CLI is an
**operational processor** over the production `network_events` SQL table
written by HTTP and Redis Streams ingestion.

1. **Migrate first**: `networkpulse db upgrade` after a DBA-verified backup
   (`pg_dump` for PostgreSQL; built-in backup for SQLite).
   Revision `0005_mlops_drift_runs` adds an append-only model/window/snapshot
   evidence table without touching flow alerts or case assignments.
2. Pin **a trusted, locally created and reviewed model** by exact
   `MODEL_SHA256`. The worker compares digest *before* loading the joblib
   artifact; joblib/pickle remains unsafe for untrusted third-party files.
3. Run `networkpulse mlops-monitor --interval 300 --lookback-hours 3
   --delay-minutes 10` (Compose `streaming` profile includes `mlops-worker`).
   The daemon reviews up to three complete past UTC hours to tolerate restarts
   and delayed ingest. Backfill older windows with
   `networkpulse mlops-monitor --once --start 2026-10-14T00:00:00+00:00
   --end 2026-10-14T01:00:00+00:00`.
4. **Admin only**: `GET /api/v1/mlops/drift-runs` returns paginated reports;
   the SOC dashboard includes a compact monitoring summary. Viewer and
   Analyst tokens cannot read model monitoring evidence.
5. Each report is uniquely tied to model SHA, UTC bounds and SHA-256 digest
   of every persisted flow ID included, in chronological order. Every
   committed flow in the window is used, not a synthetic substitution or
   silent random sample. Duplicate worker runs do not create duplicate
   records. A late arrival creates a *new immutable snapshot* and preserves
   earlier reports for incident reconstruction.
6. The record includes source-system counts, PSI by known model feature,
   alert fraction and alert-budget breaches; it holds no flow IPs, original
   payloads, credentials or ground-truth labels. Unlabeled PSI cannot prove
   accuracy, improved attack detection or malicious behavior. **No automatic
   training, calibration or model promotion occurs.**

### Production operational limits

- Safety gate: 30–10,000 flow rows per report (default 5,000). Windows over
  limit fail *visibly* without publishing a biased sampled report; split
  intervals or design proper pre-aggregated model feature rollups with
  measured accuracy before enabling high-volume deployment.
- Fewer than 30 flows return `insufficient_data` and do not claim normal
  drift. This condition is printed by the worker; external log/health
  monitoring must alert when expected reports stop arriving.
- Always measure PostgreSQL p95 query latency, memory usage and model scoring
  throughput for the actual site. Configure external process watchdog and
  metrics alerts, and explicitly backfill outages older than the 3-hour
  periodic revisit. This is not automatically verified by GitHub CI.
- The existing registry promotion gate remains human-controlled and fails
  closed for insufficient independent-site evidence. A strong drift signal
  is a *review prompt*, never automatic promotion.
- Source data labels are not persisted in the production ingest table. Real
  UNSW-NB15 replay demonstrates identical runtime data-to-evidence plumbing;
  it does **not** prove real-world detection accuracy or independent network
  generalization.

### Deployment-to-runtime preflight (single node)

Production API startup and the production Compose streaming/MLOps processes
now verify the actual deployed model SHA-256 against BOTH the pinned
`MODEL_SHA256` and the registry's active candidate before loading/scoring.
They refuse missing registry state, unresolved release journal, synthetic
candidate records, tampered registry artifacts, or incompatible feature
contracts. Set `NETWORKPULSE_MODEL_REGISTRY_ROOT=/app/data/registry` on
every scoring and MLOps service, with the same `model_data` volume mounted.
The production Compose TLS overlay configures this for API, streaming worker
and MLOps worker.

After an independently approved, signed production release is installed via
the controlled maintenance procedure above, the operator can run a read-only
preflight before starting processes:

```bash
networkpulse model-registry preflight \
  --root /app/data/registry --active /app/data/model.joblib \
  --expected-sha256 '<operator-verified-active-model-sha256>'
```

Failure codes: `NP-REL-001` missing/invalid pin, `NP-REL-002` missing
registry root, `NP-REL-003` registry/pin disagreement, `NP-REL-004`
incompatible feature contract and `NP-REL-005` synthetic/demo record.
Registry integrity/journal errors fail closed as before. This does not
authorize an unsigned release; the registry must already reflect the signed,
operator-approved deployment. Registry files and model artifacts must be
protected against unauthorized local filesystem writes.

The consistency check is read-only and single-node. A rolling,
multi-replica upgrade, in-place model replacement while requests are live,
external health-gated canary, trust-store distribution and independent site
validation are NOT implemented by this gate. Always quiesce processes for
release changes, restart all model consumers together and verify health.
