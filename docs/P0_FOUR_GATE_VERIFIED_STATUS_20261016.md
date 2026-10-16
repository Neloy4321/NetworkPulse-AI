# P0 final four-gate execution report — 2026-10-16

**P0 OPERATIONAL ACCEPTANCE: NO-GO.**
This is a factual closeout of engineering and observable external blockers,
not a signed acceptance certificate or a fabricated four-gate completion.

## Gate 1 — Fresh numeric validation: FAILED / insufficient attack support

The original **unsigned source-calibrated V2 RandomForest**, SHA-256
`cd239783fd4318c0c4e897f1d451c2d5af4b42132979c79a4e489df626f538a5`,
cutoff **0.20**, was trained from the previously exposed source only.
Calibration source FPR upper95 **2.3038%** and recall lower95 **97.0361%**
are **NOT external test results**.

Before scoring, two new original official IoT-23v2 scenarios were registered:
Capture **42-1 Trojan** and Capture **4-1 Philips Hue benign**.
Their raw source SHA-256s, after authentic retrieval:
- 42-1: `269fa1b22d9a37e159cf41b81a213a0032d21306f5d39b4c20cb0d211b04e8aa`
- 4-1: `aebe40ea0e03b120265a5c7bc140dd9b0d3fe2fce65559e84776b7dd5360e71e`

Actual same-lab transfer experiment:
[GitHub Actions run 38914466613](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/38914466613)
SUCCESS with **12 source/calibration+evaluation unit tests and Ruff lint**.
Official source taxonomy used `Benign` and lower-case `benign`;
case normalization only was fixed, no model or threshold updated.
Evidence ZIP artifact ID **12052131332**, aggregate-only, no IP/UID records.

| New laboratory source | Benign | Attack | TN | FP | FN | TP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Trojan 42-1 | 4,420 | **6** | 2,439 | **1,981** | 0 | 6 |
| Philips Hue benign 4-1 | 452 | **0** | 338 | **114** | 0 | 0 |
| **Combined** | **4,872** | **6** | **2,777** | **2,095** | 0 | 6 |

Combined benign observed **FPR ~43.00%**, versus allowed FPR
upper95 **<=5%**; naturally labeled attacks were only **6** versus
minimum 100, so Recall confidence bound is **BLOCKED**, not PASS.
This is a severe across-device false-alarm generalization failure and
cannot justify any signed release. Both test scenarios are laboratory
data from the SAME CTU Stratosphere dataset family as source IoT-23v2 34-1;
neither is a separately operated real production site.

These scenarios have now been opened/observed, so any future tuning
using their outcomes must declare them development data and reserve
another new sealed test dataset. No benchmark cherry-picking permitted.

## Gate 2 — Signed release: CODE VERIFIED, REAL SIGNING NOT COMPLETED

New V2 signed model runtime and isolated inference API require:
- exact out-of-band model SHA, immutable training feature contract,
- trusted Ed25519 approval and human independent-site/label claims,
- FPR Wilson upper <=5% AND recall Wilson lower >=80%,
- HTTPS OIDC bearer authentication and production-only startup,
- no legacy model fallback.

[Signed CI run 38910891368](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/38910891368)
passed **18 synthetic signing/unit tests plus lint** (original, now
extended with real-server probe tests).
The only signatures in tests were **ephemeral synthetic CI fixtures**.
No real operator has signed an actual final release; model SHA
`cd2397...` remains **unsigned research-only**.

## Gate 3 — Real deployment: CONTAINER PREFLIGHT DONE, HOST NOT DEPLOYED

Nonroot isolated V2 inference OCI Dockerfile,
loopback-only TLS-ingress-ready Compose template and external signed
active-host HTTPS/OIDC parity probe have been implemented.
[OCI container preflight run 38913649557](https://github.com/Neloy4321/NetworkPulse-AI/actions/runs/38913649557)
verified:
- image builds and contains no operator signing keys or model file,
- unsigned/unauthenticated production startup fails closed,
- Compose refuses empty operator credentials.

The HTTPS/OIDC external active parity probe is
`networkpulse/evaluation/v2_signed_active_probe.py`, with synthetic
network mocks for its unit tests.
**No accessible real cloud deployment, private production OIDC issuer,
independent operator signing key, valid signed receipt, SOC sensor stream
or actual field service URL exists in supplied project access.**
Building a container inside GitHub Actions is not active deployment.

## Gate 4 — Overall independent operational acceptance: NO-GO

Mandatory still absent: a genuinely **independently operated field
site** and its independently adjudicated class-supported genuine
Zeek/Suricata labeled sensor flows over multiple days; real signed,
SHA-equivalent deployed model with TLS/OIDC and actual workload alert
evidence; human audit and release signoff.

UGR'16 provides real ISP background traffic but attack examples
were synthetically injected and flows use unidirectional NetFlow v9,
not verified V2 Zeek semantics. IoT-23v2 provides public laboratory
research data, not a separately operated production SOC. Neither
can truthfully stand in for every missing operational gate.

**No automatic PASS. No quality-threshold lowering. No fake human
signature or production metrics. No change to `main`; PR #26 is draft.**

When real operator-controlled service access and independent site
evidence become available, run the provided signed factory and
external TLS model-parity probe, then produce independently checked
quality and deployment receipts. Without those resources, only a
separately labeled **public-dataset ML benchmark** can be completed.
