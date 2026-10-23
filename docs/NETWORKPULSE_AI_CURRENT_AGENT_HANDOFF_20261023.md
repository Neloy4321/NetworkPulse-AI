# NetworkPulse-AI — Current agent handoff / P0 ML acceptance (2026-10-23)

**Most recent genuinely verified disposition: `OPERATIONAL_ML_P0=NO_GO`.** This handoff index is for another engineering agent; check the links and CI before acting. Do not mistake a historically passing aggregate for complete numerical, site, or signed deployment acceptance.

## Immutable Git position

- PR [#40](https://github.com/Neloy4321/NetworkPulse-AI/pull/40): original frozen RF real FPR/Recall baseline merged.
- PR [#41](https://github.com/Neloy4321/NetworkPulse-AI/pull/41): source-trained ExtraTrees FPR repair merged.
- PR [#42](https://github.com/Neloy4321/NetworkPulse-AI/pull/42): signed-off evidence **checks** (not human signing), numerical research truth gate merged.
- PR [#43](https://github.com/Neloy4321/NetworkPulse-AI/pull/43): locked Apr15–17 later-day **RECALL FAIL**, true source artifact and fail-closed tests merged to `main` at `f25b007afa3fcd4309dd7937f7206b268eae8b88`. Five PR-head CI workflows successful.
- **Leave draft #25/#26 alone**: #26 is based on #25's branch; do not force push or merge research PRs merely to clear the board. Legacy live/default IsolationForest was not promoted/replaced.

## Real model/data/evaluation facts

**IoT-SFC source:** [Zenodo record 23371775](https://zenodo.org/records/23371775), official ZIP `iot_dataset_v7.zip` 776,500,807 bytes SHA256 `070b1356e5bd296e584109fae79139cfe0f20ff4790f69e42994d67362cb9f62`; 87 fields, `log_type=conn` (not `conn.log`), real connection-flow aliases `orig_h/orig_p/resp_h/resp_p`. Source owner permission to use for research **with citation is reported by the user**, not independently inspected written legal evidence. Original raw records and model binary are NOT committed.

**Original frozen research RF:** SHA256 `cd239783fd4318c0c4e897f1d451c2d5af4b42132979c79a4e489df626f538a5`, threshold `0.20`. On the first 200k original source CSV rows, 90,252 candidate flow scores: TN24,465/FP53,828/FN721/TP11,238; benign observed FPR **68.75%**, 95% upper **69.08%** (**FAIL**), recall **93.97%** (lower **93.53%**). [Real run 39916710997](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/39916710997); artifact 12485157606.

**New ExtraTrees research model (distinct from RF):** SHA256 `ecc320bc693481fc45b143b48ffbebcb117899e888e4687930f3361501af6fa1`, cutoff **0.90**, trained using prior exposed IoT-SFC source flows through Apr8 and selected using Apr10 development labels; *NOT signed or deployed*. On Apr12–14, 341,759 producer-labeled connection flows: TN120,141/FP5,085/FN2,547/TP213,986; FPR **4.0607%** (upper95 **4.1714%**), recall **98.8237%** (lower95 **98.7775%**). These two **aggregate pointwise research numerical bounds PASS**. Yet Apr13 FPR upper95 **7.2086% FAIL**; Apr12 has zero attacks and Apr14 only one benign; producer labels not independently adjudicated and 121,320 train/DEV hostgroup overlaps were documented. Evidence: `docs/P0_IOT_SFC_V7_VERIFIED_NUMERIC_GATE_20261023.json`, [run 39921326610](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/39921326610), PR #41.

**LATEST locked new later-day test uses the SAME ExtraTrees binary SHA and 0.90 cutoff on Apr15–17, with no tuning:** 156,362 scored producer-labeled flows, TN155,221/FP119/FN432/TP590; FPR **0.0766%** (upper95 **0.0917%**, FPR gate PASS) but recall only **57.7299%** (lower95 **54.6779%**, **RECALL GATE FAIL**). Apr15 misses 419 of 569 attacks (recall 26.36%); Apr16 has one attacked flow; Apr17 recall 97.12%. The first 450k exposed source rows were skipped, next 9m scanned; max first 60k valid unique conn flows/day. Genuine result: [run 39925211304](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/39925211304), artifact **12488319488**, report member SHA `5c3ff1101a64ddab20ac45229122ec12c4cd5f13bf47561f06af3f2e5bafc004`, pinned in `docs/P0_IOT_SFC_V7_APR15_17_LOCKED_RECALL_FAILURE.json`. **No robust multi-day recall acceptance, even within this lab.**

## Start here in order

1. `docs/P0_ML_ACCEPTANCE_RESULT_AND_GATES_20261023.md` (includes historical aggregate success AND newer recall-failure update).
2. `docs/P0_IOT_SFC_V7_APR15_17_LOCKED_RECALL_FAILURE.json` (most recent).
3. `networkpulse/evaluation/iot_sfc_locked_later_days.py`, `iot_sfc_chronological_fpr.py`, `iot_sfc_domain_adapt_fpr.py` for frozen scoring/training lineage.
4. `networkpulse/feature_contract_v2.py`, `networkpulse/evaluation/iot_sfc_v7_conn_adapter.py`, `iot_sfc_frozen_score.py` for cross-source feature semantics.
5. `docs/P0_EXTERNAL_ACCEPTANCE_HOLDOUT_REQUEST.md`, `docs/P0_FOUR_GATE_VERIFIED_STATUS_20261016.md` for real operational requirements.
6. Actual GitHub Actions checks, source ZIP hashes and run artifacts; do not silently replace original bytes or models.

**Highest priority engineering:** find why the unchanged ExtraTrees misses **419/569** April 15 attacks while preserving benign FPR and Apr17 recall. Analyze label provenance/attack family, environment/source time, group and feature drift, missingness and exact source semantics in aggregate only. Already tested labels/dates are **exposed**, so improvement on these is development—not independent final acceptance. Build a proper source training, **group+time isolated** validation/repair with predeclared threshold selection, and reserve an actually *new*, untouched independent holdout. Never optimize directly on the previously exposed test and claim virgin PASS.

**Operational gate remains blocked** until an independent field site and human-adjudicated traffic labels, benign FPR upper95≤5% and attack recall lower95≥80% on the same genuinely prospective and representative test, no leakage and adequate per-day/site support, and approved actual human-signed identical model running over real TLS/OIDC with authentic Zeek/Suricata, SOC alert burden, rollback and operator receipt. Synthetic signing/staging CI is not field proof.

**Security:** Earlier Cloudflare R2 credentials appeared in chat; rotate and use GitHub Actions read-only bucket scope. Never commit joblib/pickle, raw traffic, IPs/UIDs or credentials.

**Secondary past readiness figures:** an older Oct15 handoff had 12 subjective engineering-progress categories with ~88.4% arithmetic average; this is NOT current measured readiness or an acceptance certificate. Avoid recycling it without current source-backed reassessment.

**Immediate successor check:**
```bash
git fetch origin --prune
git switch main && git pull --ff-only origin main
git rev-parse HEAD
gh pr list --repo Neloy4321/NetworkPulse-AI --state open
gh run list --repo Neloy4321/NetworkPulse-AI --branch main --limit 12
```
Start work on a **new feature branch** and merge only with proven exact-source runs, fail-closed CI, real result artifacts, review and preserved original release status; never force-push main.
