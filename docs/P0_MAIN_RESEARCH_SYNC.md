# Completed engineering synced to main (2026-10-16)

This sync contains **non-default, research-only** NetworkPulse ML evidence, native
Private-R2 source access helpers, the V2 missingness-aware Zeek/Suricata feature
contract, the opt-in signed-inference adapter, tests, Docker staging templates
and truthful outcome reports.

The existing default production IsolationForest detector, current deployment
and core main-line API are **not promoted or replaced**. No researcher trained
model is an approved active production model. Genuine trusted operator signing,
independent field SOC/site validation, numerically qualified model and real
cloud deployment are **NOT complete**.

**Why PR #25's native cross-dataset workflow is intentionally NOT copied:**
its real-data test ran on TON traffic and correctly failed the numerical gate
(21.875% observed FPR, Wilson upper ~25.79% versus <=5%). The training/
data-access helpers and unit tests that passed are preserved, without
pretending this red P0 acceptance gate passed or silently weakening it.
The failing research work remains accessible in PR #25.

**Why PR #26's README patch is not transplanted:** its text describes the
stacked PRs as entirely unmerged and would be stale if synced here. The
verifiable details are in the P0 docs and original PR/workflow history.

The experimental V2 workflows use workflow_dispatch, plus their original
stacked research-branch filters, and are not an assertion that P0 acceptance
succeeded on main. Quality gates for main remain required before merge.

- [P0 research audit](P0_FOUR_GATE_VERIFIED_STATUS_20261016.md)
- [Signed research V2 handoff](P0_SIGNED_V2_SOURCE_CALIBRATION_HANDOFF.md)
- [Verified V2 real data failure](P0_V2_ACTUAL_MODEL_REPAIR_AND_LAB_RESULTS.md)
- [Unresolved P0 blockers](https://github.com/Neloy4321/NetworkPulse-AI/issues/27)
