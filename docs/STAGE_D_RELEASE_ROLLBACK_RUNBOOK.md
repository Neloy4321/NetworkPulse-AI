# Stage D — Disposable Non-ML Release/Promotion/Rollback Gate

This is an **ephemeral CI-only, model-free release control experiment**. It does not publish a GitHub Release, deploy NetworkPulse-AI to a server, sign an OCI image, change an active ML model, or claim production availability.

## Tested release lifecycle

- Three disposable `python:3.12-alpine` services run in a uniquely named Docker Compose project, host-port bound to `127.0.0.1`: stable, candidate, and route-aware gateway.
- Every service explicitly reports `model_loaded=false`, the isolated test scope and a fixed synthetic release fingerprint. These are fixture payload fingerprints, **not signed image digests or immutable production artifact attestations**.
- The operator-gated orchestrator requires a default local Docker socket in GitHub Actions, an exact consent string, a per-run scoped project and a dedicated CI route directory initialized to `stable`. It can kill only the candidate container after validating Compose project/service labels, image name, container ID and loopback-only port. It will not touch production, ML workers or existing Docker services.
- Before promotion, independently check real HTTP readiness and release fingerprints from both fixtures, and require the gateway is serving stable. Refuse a bad expected fingerprint without modifying the active route.
- Atomically switch a single dedicated local route file to candidate, using exclusive-create staging, `fsync` and `os.replace`, then demand live HTTP traffic from the candidate through the gateway.
- **SIGKILL** the actually running owned candidate container. Verify the gateway fails closed with HTTP 503 rather than silently claiming a healthy release; stable must remain healthy.
- Roll back the route pointer to stable; demand healthy gateway traffic and exact original pinned stable fingerprint, zero ML operations, and that the dead candidate cannot be treated as healthy.
- Upload only metadata-only JSON evidence with observed disposable promotion/rollback durations; delete the temporary route and the owned disposable CI services and volumes.

This is **a synthetic routing/gating prototype, not automatic failure detection or rollback in a live cluster**. The orchestrator performs rollback after observing failure; there is no externally deployed watchdog, approval process, distributed service discovery, real release signing, artifact provenance pin, multi-node HA, multi-replica draining or production incident SLO.

## Verification / merge contract

The `Stage D model-free isolated release promotion and real rollback` workflow must show actual Docker runtime PASS, not just unit mocks; Python 3.11/3.12 project quality, Browser E2E and existing crash recovery regression must remain green. Never merge if the critical gate fails. No operator permissions, real hosted environment or production credentials are used.

ML P0 cross-dataset generalization remains NO-GO; Stage D CI is not evidence that a frozen ML model can be rolled out safely.

## Branch integration

See `docs/UNMERGED_BRANCH_AUDIT.md`. Existing unfinished ML research PRs are intentionally separate; do not squash every historical branch blindly into `main`, especially where code has already landed through previous squashed PRs or where external evaluation acceptance is missing.
