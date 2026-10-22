# Branch integration and main merge safety audit (2026-10-22)

Repository: `Neloy4321/NetworkPulse-AI`
Last verified baseline before Stage D: `main@345d7e97185cd894f100018a75d7ae15cd96deb8`.

## What was inspected

- Enumerated **all 31 non-main branch refs** returned by GitHub (prior to creating Stage D).
- Read each remote Git tree recursively and compared **tracked file paths and blob SHA values** to that precise `main` tree.
- Checked all open PRs, their draft/base/head status and changed-file lists.

**Result:** all 31 audited historical branches have **zero file paths not already present in main**. This does **not** establish that every byte on each branch is merged: older branch heads differ from current `main` in many existing files. Wholesale merges, especially overwriting newer security/workflows/ML evaluation, would therefore be unsafe.

### Branches whose tracked blob content matched main exactly during the audit
- `integration/completed-p0-research-20261016`
- `feature/stage-a-nonml-staging-foundation`
- `feature/stage-b-nonml-event-integrity`
- `feature/stage-b-real-container-restarts`
- `feature/stage-b-encrypted-scratch-restore`
- `feature/stage-c-alertmanager-delivery-ci`

### Branches with stale or divergent existing-file content (not safe to blindly merge)
- `copilot/fix-native-cross-dataset-job` and `feature/p0-source-only-audit-benchmark` (open ML PR sources)
- `feature/collector-rotation-continuity-recovery`
- `feature/durable-behavior-cases-20261014`
- `feature/durable-cross-window-incident-correlation-20261014`
- `feature/isolated-node-sigkill-recovery-drill`
- `feature/isolated-staging-sustained-load-gate`
- `feature/ml-external-generalization-deployment-evidence`
- `feature/operational-behavior-analytics-20261014`
- `feature/operational-mlops-monitoring-20261014`
- `feature/operational-stream-integrity-and-slo`
- `feature/p0-dataset-reaudit-nested-archives`
- `feature/p0-native-unsw-toniot-crossdomain`
- `feature/p0-source-only-domain-diagnostics`
- `feature/production-deployment-guards-20261014`
- `feature/reproducible-training-releases-20261014`
- `feature/runtime-model-release-preflight`
- `feature/signed-model-release-safety-20261014`
- `feature/stream-worker-failure-budget`
- `feature/streaming-atomic-batching-recovery-20261014`
- `feature/verified-disaster-recovery-20261014`
- `feature/worker-slo-telemetry-graceful-shutdown`
- `p0-database-integrity`
- `security/oidc-azp-docs-20261014`
- `security/real-unsw-rbac-csp-20261014`

### Open PRs (intentionally **not** force-merged)
- [#25](https://github.com/Neloy4321/NetworkPulse-AI/pull/25): **draft**, targets main; R2 native cross-dataset instrumentation and benchmark semantics. Head vs main had four differing tracked blobs, including CI native-cross-dataset workflow and two tests. Requires independent safety and dataset/evaluation acceptance.
- [#26](https://github.com/Neloy4321/NetworkPulse-AI/pull/26): **draft**, targets the head of PR #25 rather than main; contains substantial model V2 and experimental research changes and depends on unfinished #25. Head vs main had four differing tracked blobs at audit time, including existing workflow/README/test files. ML P0 external generalization remains **NO-GO**. **Neither PR qualifies for an unconditional main merge**.

## Exact safe integration policy

1. Stage A–C prior feature content was already in main; do not re-add or rebase stale branches just to remove branch refs.
2. Integrate **new, independent Stage D code only through a green PR** with true disposable Docker CI, Python Quality (3.11/3.12), Browser E2E and crash-recovery checks; verify main again post-merge.
3. Keep #25/#26 and any other old branch content requiring independent acceptance untouched until it is validated against **current** main and current security contracts.
4. No change to the **P0 ML NO-GO** gate, no assumed production model approval, no auto-merging failing or draft research work.

**Important:** Comparing file inventory + blob hashes is a scope and safety audit, not complete behavioral equivalence or a formal commit ancestry/merge-base proof. Earlier commits may remain reachable only through old branch histories even if their final code was incorporated via squash into main.
