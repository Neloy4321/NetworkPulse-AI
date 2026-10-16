# Stage C — Real Prometheus / Alertmanager Webhook, Recovery & Silence (CI)

**Scope:** Deliberately isolated, synthetic, disposable GitHub Actions test. No production alert routing, real customer/sensor data, ML model, external on-call integration or live HTTPS/OIDC. Existing production Prometheus rules and compose stack are **not changed**.

## Tested path and trust boundaries

- Actual Prometheus v2.55.1 scrapes a standalone, model-free HTTP exporter once per second. Its only metrics are CI-only `networkpulse_ci_synthetic_dependency_up` and `networkpulse_ci_synthetic_muted_probe`.
- Actual Prometheus rule evaluation triggers two uniquely named, clearly labeled synthetic alerts. Actual Alertmanager v0.28.1 receives firing and resolved events.
- Actual Alertmanager delivers webhook notifications to the isolated receiver on a private Docker network, sending an ephemeral Bearer token through its `credentials_file` configuration. Requests lacking that token are rejected, including forged webhook and acknowledgment attempts.
- All three service ports are host-**loopback-only** and the temporary token file is readable only by the disposable service user. No public domain, IP, external mail/SMS/Slack destination or production secrets are configured.
- The receiver retains only bounded alert fingerprints, alert names, firing/resolved status, and synthetic acknowledgment metadata. No raw webhook bodies, credentials, network-flow payloads or model results are persisted in the uploaded CI evidence.

## End-to-end sequence

1. Refuse non-GitHub CI, missing consent, nondefault Docker context, non-disposable project or overridden service endpoint. Verify Prometheus/Alertmanager actual readiness and successful scrape target.
2. Prove anonymous observations, synthetic ACK and forged webhook all receive HTTP 401.
3. Set **synthetic** dependency gauge to zero. Wait until Prometheus shows the alert **firing** and until an **authenticated Alertmanager firing webhook actually arrives**; observe fault-injection-to-receipt time.
4. Create an authenticated, idempotent **synthetic CI acknowledgment** of the delivered fingerprint. This is **not** a human on-call acknowledgment and has no authority to silence a live incident.
5. Restore synthetic dependency metric to one; require a real **resolved** webhook for the same fingerprint and measure recovery-to-receipt time.
6. Create a real Alertmanager **silence** for only `NetworkPulseCISyntheticMutedProbe` plus synthetic scope labels. Enable that probe, prove Prometheus firing and Alertmanager `silencedBy` membership. Confirm no webhook delivery over several `group_wait` intervals while silenced.
7. Delete the silence while that synthetic alert remains firing, require webhook delivery to resume, then clear the probe and require its **resolved** webhook.
8. Upload metadata-only PASS/FAIL report, report measured timings as **ephemeral CI-only observations**, destroy test containers and delete ephemeral token.

**Important semantics:** Alertmanager silences suppress notifications. They are **not acknowledgments**. The receiver's token-authenticated `/ack` ledger proves a simulated acknowledgment API only; there is no genuine human/operator workflow. Neither proves real on-call paging, escalation, 24–72 hour soak, site-specific SLO, production MTTA nor end-user acknowledgment. No increase to historical 12-category readiness percentages is warranted without full re-audit.

## How to verify

Run `Stage C real Prometheus Alertmanager webhook and silence CI` via pull request or workflow dispatch. Confirm all steps PASS, inspect its uploaded metadata JSON and matching git SHA, and verify the existing Python quality, browser E2E and isolated crash recovery tests remain green. Failure, notification loss, authentication bypass or silence inconsistencies are **NO-GO** for this slice.

## Still not complete

Actual operator-managed external delivery (email/SMS/Slack/PagerDuty), real notification acknowledgment and escalation, deployment-specific alert rule SLO calibration, authentication/authorization for operational dashboards, offsite retention/DR, real DNS/TLS/OIDC staging, soak and independent human acceptance all remain pending. ML P0 stays NO-GO.
