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
