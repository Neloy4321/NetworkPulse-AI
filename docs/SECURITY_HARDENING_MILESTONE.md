# Earlier security hardening snapshot

> This document describes an earlier phase. For current SSO/HTTPS implementation,
> see [deployment runbook](DEPLOYMENT_SSO_TLS.md) and
> [penetration-test handoff](PENETRATION_TEST_HANDOFF.md).

# Authentication & Security — security hardening milestone

**Status:** Focused defensive improvements committed, tested and documented.
This is a research/engineering prototype, not a penetration-tested production SOC.

## Verified changes

| Security concern | Control shipped | Evidence |
|---|---|---|
| Peer-churn limiter bypass | Max 10,000 active peer buckets and fail-closed refusal | `tests/test_security_hardening.py` |
| Oversized/chunked request responses | Existing bounded streaming; early reject paths now receive protective headers | `tests/test_security_hardening.py`, existing request body tests |
| Browser content policy | CSP, anti-framing, anti-sniffing, no-referrer, Permissions-Policy, no-store | API integration tests |
| Exported formula injection | Spreadsheet-dangerous leading operators sanitized after whitespace/BOM | `tests/test_csv_export_security.py` |
| Oversized JWT parsing | Reject token length outside 20–8,192 before JWKS lookup | `tests/test_oidc_token_bounds.py` |
| Missing JWT subject | Verified token requires nonblank `sub` | `networkpulse/security/oidc.py` |
| Known demo API key in .env | Reject built-in example/placeholder and padded local secrets | `tests/test_placeholder_secrets.py` |
| Vulnerable dependencies and static review | `pip-audit` and `bandit` on security-sensitive push + weekly | [Security CI](https://github.com/Neloy4321/NetworkPulse-AI/actions/workflows/security-audit.yml) |

## Important boundaries

**No browser SSO was deployed.** The existing OIDC JWT API authorization and
role-mapping tests already existed before this milestone. HTTPS IdP setup and
an interactive browser Authorization Code + PKCE flow are still required for
remote multi-user SOC use. A proposed large browser-integration change did
not pass the repository write security check and **was not committed**;
this report does not describe it as implemented.

**No new production runtime or public server was deployed.** Default Docker
Compose serves the API on host `127.0.0.1:8000`, but local read routes
intentionally have no read authentication. Avoid public exposure; do not
assume a proxy automatically supplies CORS, CSRF, session security or access
control. IP-based limiter buckets are per API worker and can group legitimate
clients behind one reverse proxy. Apply a gateway Redis/distributed limiter
and enforce a trusted proxy model before horizontal scaling.

Security response headers help enforce browser isolation but do not by
themselves prevent XSS if dangerous application logic is introduced.
CSV formula prefixing guards the exported spreadsheet interpretation, not
arbitrary downstream transformations which strip the apostrophe.
JWKS verification and JWT freshness remain dependent on IdP availability and
proper issuer/audience configuration.

## User-controlled setup

For the existing **local development** workflow, no credentials need to be
provided to the assistant. Check that `NETWORKPULSE_API_KEY` in the private
`.env` is **not** the repository's documented example. If it still is,
generate a strong random value locally, replace it privately, then restart
only the local services that read the environment.

For genuine **multi-user** deployment, the user must choose an OIDC provider
(e.g. Microsoft Entra ID, Keycloak or Auth0), establish a HTTPS hostname, and
manage the registered client. None of those account-specific configurations
can be safely invented or automatically verified from the code alone.

## Pending Security Requirement #3 gates

- Fully operational browser login, logout, PKCE and state-bound session flow
- Secret rotation / invalidation and browser-session CSRF architecture
- Remote TLS/reverse-proxy hardening and multi-replica distributed rate limits
- End-to-end IdP role mapping and per-tenant authorization review
- External penetration test, threat validation and incident-response drills

**Engineering completion remains below 100%.** This phase closes several
targeted implementation gaps but does not certify readiness for public use.
