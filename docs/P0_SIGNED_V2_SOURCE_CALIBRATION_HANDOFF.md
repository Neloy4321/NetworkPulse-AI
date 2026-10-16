# P0 ML — signed V2 admission + source calibration handoff (2026-10-16)

**No operational acceptance has yet been demonstrated.** This record is
about verified engineering work; do not relabel synthetic signed CI receipts
as an actual site's independent human-approved evidence.

## Genuine source calibration result

[Successful GitHub Actions run #38909855312](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/38909855312)
ran original full-byte-pinned UNSW + IoT-23v2 Capture 34-1 sources,
with a deterministic host-pair/protocol-group-disjoint FIT/CAL partition.
The source split **does not score Hakai 8-1, Torii 20-1, TON-IoT, CIC
or an independently operated site**. Ruff and six focused tests passed.

- Source FIT: 41,670 flows, 17,797 benign / 23,873 attack.
- Source CAL: 5,026 flows, 4,683 benign / 343 attack.
- Internal FPR safety budget: 95% Wilson upper <= **2.5%** (stricter
  than the external <=5% acceptance requirement).
- Fixed predeclared threshold grid in steps of 0.025 from 0.05 to 0.95.
  First FPR-admissible threshold selected: **0.20**.
- Source CAL confusion: TN **4,592**, FP **91**, FN **5**, TP **338**.
  Source CAL observed FPR **1.9432%**, Wilson upper **2.3038%**;
  attack recall **98.5423%**, Wilson lower **97.0361%**.
- The candidate model is **unsigned research-only**, source group calibration
  is not independent site testing, and the 343 attacks can share temporal/
  behavioral correlations; Wilson may be overconfident.
- Source-calibrated model SHA:
  `cd239783fd4318c0c4e897f1d451c2d5af4b42132979c79a4e489df626f538a5`.
  Aggregate evidence artifact **12049488464**, unsigned bundle artifact
  **12050072139**, artifacts are temporarily retained by GitHub Actions.
- The training/model/threshold receipt is never changed to claim the
  earlier original Hakai 8-1 score (77.54% recall) has now improved by 4%.
  That capture was already exposed before this new calibration protocol.

**Release NO-GO:** Source-only numerical success can justify preparing
the next untouched evaluation; it cannot certify independent operator
ground truth, a digitally approved production model or deployment.

## Signed production-compatible V2 scoring code

`networkpulse/v2_signed_runtime.py` and `networkpulse/v2_signed_api.py`
implement an opt-in, separately versioned API route, never silently
falling back to the existing IsolationForest service.

[Signed runtime CI run #38909008277](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/38909008277):
**17 synthetic-only signature/HTTP-auth tests passed plus Ruff**.
Only ephemeral CI private keys and invented numeric evidence were used
to exercise fail-closed code; these are **not production trust anchors**.

Actual operator deployment entrypoint:
```bash
uvicorn 'networkpulse.v2_signed_api:create_production_v2_app' --factory \
  --host 127.0.0.1 --port 8200
```

The operator must provide a real production `Settings.from_env()` config
with HTTPS OIDC issuer/JWKS, along with **ALL** these secure runtime inputs
as environment variables. Paths refer to operator-controlled private
mounted files, not public GitHub build artifacts:

- `NETWORKPULSE_V2_ACTIVE_BUNDLE` — exact trusted frozen model joblib
- `NETWORKPULSE_V2_FROZEN_MANIFEST` — matching SHA/protocol/feature contract
- `NETWORKPULSE_V2_SIGNED_APPROVAL` — current trusted Ed25519 operator envelope
- `NETWORKPULSE_V2_OPERATOR_TRUST_STORE` — independently provisioned public key
- `NETWORKPULSE_V2_MODEL_SHA256` — reviewed, out-of-band model SHA-256

The actual signed promotion receipt must be validated with
`networkpulse.release_approval.verify_signed_approval` first; it binds
the exact candidate SHA and states independently verified site,
live sensor contract and train/test leakage audit. The `evaluation`
object is additionally required to hold **genuine** `benign_count`,
`attack_count`, `false_positives`, `true_positives`,
`feature_contract="missingness_aware_flow_v2"`,
`dataset_kind="independent_operator_site"`,
`labels_independently_reviewed=true`,
`deployed_sensor_parity_checked=true`, and at least
`distinct_capture_days=2`.

Required quality conditions: natural benign support >=200; attack support
>=100; FPR Wilson 95% upper <=5%; attack Recall Wilson 95% lower >=80%.
The API cannot be activated without SHA equality, authenticated
operator-signed receipt, eligible model/protocol, and genuine OIDC auth.
A signed JSON string that **claims** evidence is insufficient to prove
the facts; its provenance must be independently audited.

The active runtime serves only `FlowV2` at
`POST /api/v2/score`, requiring an OIDC bearer principal with
`analyst` authorization. It emits probabilities and decisions, not
raw IPs or network UIDs. The existing main deployment is NOT modified.

## Remaining unavoidable P0 evidence blockers

1. **Fresh, genuinely untouched independently operated site/day** with
   native V2-compatible authenticated telemetry, truly adjudicated
   benign/attack labels and no leaked training groups.
   Stratosphere/UNSW are controlled laboratories.
   UGR'16 (https://nesg.ugr.es/nesg-ugr16/) offers real Spanish ISP
   background but synthetic/injected attack flows and **unidirectional
   NetFlow**, not native bidirectional Zeek/Suricata records. A rigorous
   new sensor contract/semantic validation is required before it can be
   used; no absent reverse-direction counters may be fabricated.
2. Real accountable human approval and security-managed Ed25519 private
   signing key (NOT a CI test signer), separate trust store and bounded
   signed receipt; no claim these exist unless an operator supplies them.
3. A real controlled staging/production host and secured OIDC/TLS identity
   provider, deployed SHA-identical signed model, physical sensor parity,
   live alert workload, per-day/site evidence, SLOs, rollback, analyst
   review, and persistent operational evidence. No real deployed host
   evidence currently exists.
4. Previously exposed R2 upload credentials should be rotated for a
   bucket-scoped read-only CI token.

**Overall decision: NO-GO until these are actually demonstrated**.
A synthetic CI signature or source-development 97% recall cannot count as
independent operational ML acceptance.
