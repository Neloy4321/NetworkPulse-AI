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

### Production policy gate (NOT an independent attestation service)

The default `promote` command continues to support an explicit **local/demo**
workflow and is **not** production certified. To opt into the more restrictive
policy:

```shell
networkpulse model-registry promote --production --name validated-candidate --active data/model.joblib --max-fpr-upper-95 0.05 --evidence data/operator-verified-validation.json
```

The receipt must contain a matching registered artifact SHA-256,
`independent_site_verified: true`, `live_sensor_contract_verified: true`,
`training_test_leakage_audited: true`, a nonempty `approved_by`, and
`evaluation` with `benign_count`, `attack_count` and
`false_positives`. A minimum of 200 benign and 30 attack examples is
enforced; the computed one-sided 95% Wilson upper FPR must meet the budget.
Synthetic-only artifacts fail regardless of their F1. Receipts are checked
before any model artifact is replaced.

**Critical trust boundary:** those boolean declarations and operator names
come from a local JSON file. The software **cannot independently authenticate
the evidence source, site independence or the approver**, nor cryptographically
verify an independent lab's signatures. A real change-management process,
source validation, secure identity and a reviewed approval process remain
mandatory for production operations. The runbook does not claim otherwise.
