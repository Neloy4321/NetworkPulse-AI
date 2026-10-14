# OWASP ZAP local passive baseline — warning triage (2026-10-14)

This is a review of the nine **category names** recorded in
[`local_zap_baseline_2026-10-14.json`](../reports/security/local_zap_baseline_2026-10-14.json)
and the matching [workflow](../.github/workflows/authorized-dast.yml).
The scan exercised **HTTP 127.0.0.1:8000 in local development mode**, using
synthetic data. These categories alone do not identify a particular vulnerable
request. Individual URL/evidence review and a fresh authenticated HTTPS scan
are still required. None of the following is an independent penetration test.

| Warning category (ZAP ID) | Triage / disposition |
| --- | --- |
| Cross-Domain JavaScript Source File Inclusion (10017) | **Likely development Swagger UI** loads third-party resources; check the per-URL JSON report. Production disables Swagger/OpenAPI in the FastAPI app and Caddy also blocks these routes. **Environment-specific; verify again.** |
| Information Disclosure - Suspicious Comments (10027) | **Unresolved.** Review the exact flagged response/comment and remove any internal/sensitive content; do not assume a code comment alone is a leak. |
| Content Security Policy Header Not Set (10038) | Development Swagger docs intentionally have different CSP needs. **Unresolved for development docs;** production docs are now disabled at FastAPI and the gateway. Verify exact URL. |
| Non-Storable Content (10049) | Review alert URLs for conflicts between `no-store`, cache-related headers and sensitive responses. `no-store` is intentional for auth and SOC data; **verify individual instances**. |
| CSP: style-src unsafe-inline (10055) | **Code mitigation committed:** remove `'unsafe-inline'` from dashboard CSP and replace the protocol legend's dynamic inline `style` attribute with JavaScript CSSOM updates. Browser CI is required to confirm compatibility; a fresh ZAP retest is still required before marking the warning closed. |
| Modern Web Application (10109) | **Informational classification**, not evidence of a vulnerability. |
| Private IP Disclosure (2) | Local loopback scan references `127.0.0.1`. **Likely environment-specific**, but confirm actual flagged response and retest staging. |
| Sub Resource Integrity Attribute Missing (90003) | **Likely development Swagger CDN**; production documentation endpoints are now disabled. Confirm URLs and either self-host or pin/integrity-protect resources wherever retained. |
| Cross-Origin-Embedder-Policy Header Missing or Invalid (90004) | Header absent in current response policy. **Open defense-in-depth review:** test `require-corp` compatibility before enabling; absence alone does not establish exploitability. |

## Changes in this review

- Production FastAPI now disables `/docs`, `/redoc` and `/openapi.json`
  even when requests bypass Caddy. Local development documentation remains.
- OIDC ID-token validation now requires `azp` to match the configured
  public client whenever more than one audience is present, and rejects a
  mismatched `azp` even with one audience.
- Regression tests cover production-vs-development docs and both rejected and
  accepted multi-audience ID tokens.

## Required completion evidence

1. Review each finding's **specific URL, confidence, evidence, and response**
   from the archived detailed ZAP artifact. The published JSON in this
   repository contains only the categories and counts.
2. Re-scan an authorized **synthetic staging system over real HTTPS** with an
   actual OIDC provider, login sessions and separate Viewer/Analyst/Admin roles.
3. Document retest outcome, any accepted residual risks and remediation
   before claiming closure. An independent assessor is still required.

**Status:** 9 warning categories *triaged at category level*, not 9 confirmed
vulnerabilities fixed. This update does not change the historical scan result.


## Real capture authenticated ingestion regression (2026-10-14)

The native UNSW workflow now replays a bounded held-out sample from **original
UNSW-NB15_4.csv** through the running FastAPI application while using a Detector
trained only from earlier **UNSW-NB15_1.csv**. The archived dataset byte size and
SHA-256 are pinned. The replay tests signed RS256 JWT identity and three role
boundaries, rejects invalid tokens, and checks authenticated ingestion,
idempotency and read protection. Only a small aggregated JSON receipt is uploaded.

**Important:** JWT signing keys and the issuer/JWKS response are test-local;
this is real **traffic data**, *not* a real external IdP, multi-worker
Redis/Caddy TLS staging, or independent security assessment. Existing real-data
model evaluation still reports real held-out detection metrics separately.
