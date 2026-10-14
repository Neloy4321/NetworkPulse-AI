# Independent penetration testing — authorization & assessor handoff

**Current status: NOT COMPLETE.** Repository unit tests, CI static audits,
dependency checks and an automated OWASP ZAP scan of a disposable locally
hosted synthetic-data application are **self-assessments**. They are not an
independent assessor's penetration test or a third-party certificate.

## Authorization, scope and prerequisites

A separate qualified tester needs the **owner's explicit written permission**
and an operator-managed HTTPS staging domain. Define an agreed testing window,
scope (hostname, API paths, authenticated user roles, containers and Redis
service), test IP ranges, rate caps, exclusions (DoS, destructive database
operations, real customer data), secure reporting channel and emergency
stop contact. Do not upload IdP secrets, private keys, .env or real network
traffic to public CI or issue comments.

The assessor should be provided synthetic test accounts for Viewer, Analyst,
Admin and an account with no NetworkPulse role. All sensitive data must be
synthetic and the database must be backed up before authorized active tests.

## Test matrix and expected proof

| Category | Representative independent checks |
|---|---|
| OAuth/OIDC | PKCE downgrade, swapped/state replay, nonce substitution, issuer/audience mismatch, ID-token substitution, JWKS rotation and expiry |
| Session | Secure/HttpOnly/SameSite flags, logout invalidation across workers, lifetime, cookie fixation, Redis restart behavior |
| CSRF/CORS | Cross-origin mutation, missing Origin/CSRF, form submission, browser preflight, attempted bearer/cookie substitution |
| Authorization | Read/triage/metrics role boundaries and IDOR across alert/assignment/history routes |
| Proxy/TLS | HTTPS redirection, headers, certificate chain, exposure of 8000/Redis/Postgres, untrusted forwarded headers, path normalization |
| Resource use | Redis fail-closed, global and per-credential shared throttles, malformed/chunked body caps, server log safety |
| Web/API | XSS in audit notes, spreadsheet formula injection, injection/error handling, sensitive model metadata and API docs |
| Supply chain | Lock/reproducibility, signed releases, image vulnerability review, model provenance/pickle risk |

For each confirmed finding require severity/CVSS, URL or component, exact
reproduction in staging, impact, anonymized evidence, remediation owner,
fix commit, retest and final signed report. No real credentials or raw
flow payloads belong in the public report.

## Acceptance gates

- No unresolved critical/high-impact authenticated bypass or sensitive-data
  exposure.
- OIDC session/PKCE, CSRF, proxy and multi-replica Redis behavior reproduced on
  the deployed staging environment.
- HTTPS origin and DNS verified; external network scan confirms only intended
  ports reachable.
- A **different assessor** signs off the authorized final report and follow-up
  remediation retest.

Until a domain/IdP/staging environment and independently engaged assessor
exist, this category cannot be called 100% complete.
