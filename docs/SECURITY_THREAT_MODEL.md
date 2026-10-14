# NetworkPulse security threat model

**Trust boundaries:** untrusted sensor logs → collector; operator browser → API; API/worker → database/model artifact; worker → Redis; OIDC identity provider → JWT verification; public GitHub → dependency supply chain.

| Threat | Implemented control | Remaining deployment controls |
| :--- | :--- | :--- |
| Malformed sensor data | Pydantic schema, port/IP/time checks, line-size checks | Fuzzing and untrusted-sensor sandboxing |
| Duplicate/concurrent ingestion | Stable hash and DB ON CONFLICT transaction | Load/stress/partition tests |
| Unauthorized mutation | Random local API key or opt-in OIDC bearer token with minimum Analyst role | User-facing OIDC login/PKCE, TLS and rotation |
| Unauthorized read | OIDC mode protects sensitive GETs and dashboard HTML | Per-tenant row-level policy, browser interactive SSO, reverse proxy |
| JWT token substitution | RS256 signature, pinned HTTPS JWKS, audience, issuer, exp, iat and role checks | IdP incident response, identity claim mapping, key rotation drills |
| Secrets in logs | Access metrics use route templates, not raw IP/query/token labels | Centralized redaction validation and access log retention |
| Malicious model artifact | Only locally trusted joblib files intended | Signing/checksum registry, provenance and sandbox isolation |
| Queue tampering | Redis group ACK after DB commit; DLQ on repeated failures | Redis TLS, auth, ACL, encrypted storage, key rotation |
| Resource exhaustion | Bounded flow batches, bounded collector backlog and 1MB log line limit | Reverse proxy body limits, distributed rate limits, quotas, WAF |
| Lack of accountability | Durable alert state audit (old/new/note/time) | Verified actor identity in DB audit, security event ledger |

## Configuration

Local mode preserves previous learning behavior (`NETWORKPULSE_AUTH_MODE=local`): the browser and read API are available only if the operator keeps Uvicorn bound to localhost; ingestion and mutations require the `NETWORKPULSE_API_KEY` secret.

OIDC mode (`NETWORKPULSE_AUTH_MODE=oidc`) requires:

```
NETWORKPULSE_OIDC_ISSUER=https://your-idp.example/realms/ops
NETWORKPULSE_OIDC_JWKS_URL=https://your-idp.example/realms/ops/protocol/openid-connect/certs
NETWORKPULSE_OIDC_AUDIENCE=networkpulse-api
NETWORKPULSE_OIDC_ROLE_CLAIM=networkpulse_role
```

Tokens must be sent as `Authorization: Bearer <OIDC access token>`. Viewer reads; Analyst ingests and triages; Admin accesses `/metrics`. **The current opt-in OIDC browser mode includes Authorization Code + PKCE, sessions and logout, but no real external IdP or HTTPS domain has been deployed/tested.** Do **not** expose local mode directly to the internet.

## Priority blockers to production

- End-to-end sign-in with a real external IdP and per-request actor audit verification.
- TLS reverse proxy, distributed rate limiting, secure cookies and CSP, security test suite.
- Secret rotation, backups encryption, monitoring, vulnerability scans and penetration testing.
- Model artifact integrity verification and rollback protocol.

## October 2026 security hardening (measured engineering slice)

- HTTP mutation limiter now caps distinct active peer buckets at 10,000,
  expires idle buckets, and **refuses new peers when saturated** instead of
  evicting active rate-limit state. This is an in-process guard, **not**
  distributed protection or defense against a large distributed DDoS.
- HTTP responses include anti-framing, content-type sniffing and privacy
  headers; the main application/API also sends a same-origin CSP. **HSTS is
  emitted only for requests observed as HTTPS**. Deployment proxy TLS and
  trusted forwarded-header handling remain operator responsibilities.
- Early 400/413/429 responses receive the same security headers rather
  than bypassing the response policy.
- SOC CSV export now treats leading formula operators after whitespace/BOM
  as unsafe. It prefixes an apostrophe before writing affected string
  cells with Python's CSV writer. Security unit/integration tests include
  multiline and leading-whitespace payloads.
- OIDC JWT decoding rejects oversized/short tokens **before** a JWKS lookup
  and rejects blank `sub` identities. Existing RS256 signature, issuer,
  audience, expiry and role validation are still enforced.
- Local-mode env parsing rejects well-known documented placeholder API keys
  and leading/trailing whitespace. Operators **must create their own random
  key locally** and never publish it or send it through chat.
- GitHub Actions now runs dependency vulnerability analysis (`pip-audit`)
  and high-severity source review (`bandit`) automatically when relevant
  files change, as well as its existing weekly schedule.

### What is *not* solved

- **Interactive browser OIDC sign-in/PKCE and logout** are implemented in code, but **real-provider integration and independent staging testing remain**.
  OIDC still protects REST APIs with externally issued bearer tokens; the
  browser dashboard is *not* a complete enterprise SSO client.
- Local development mode deliberately allows anonymous **read** endpoints
  and dashboard access, although mutations require an API key.
  Compose binds the API host port to `127.0.0.1:8000`; never open this local
  mode to a public IP or forward its port to the internet.
- Actual HTTPS reverse proxy / SSO IdP, distributed authorization and rate
  limiting, per-tenant row isolation, secure Redis/database operations,
  centralized secret rotation, and independent penetration tests are
  **not implemented / not externally verified**.
- The in-memory limiter uses the immediate TCP peer address, not
  `X-Forwarded-For` provided by an untrusted client. Behind a reverse
  proxy, external gateway limits are mandatory.
- Joblib remains pickle-based and loads only locally trusted model
  artifacts. No externally authenticated signing/attestation service exists.

### Operator security checklist

1. Change the `.env` local API key if it still equals the example placeholder.
   Generate a random value on your own device; **never provide it to ChatGPT**.
2. Keep the local dashboard on `127.0.0.1:8000` or a private development
   network. The default mode is **not multi-user production authentication**.
3. For real remote multi-user deployment, choose an OIDC identity provider
   and HTTPS application hostname, register the appropriate OAuth client,
   then separately complete browser sign-in/PKCE and hardened reverse proxy
   and session management. Do not make a public DNS entry for the demo server
   until those controls have been implemented and independently tested.
4. Review [CI security audit](https://github.com/Neloy4321/NetworkPulse-AI/actions/workflows/security-audit.yml),
   dependency results, security updates and secret-rotation procedures.

[Full milestone](SECURITY_HARDENING_MILESTONE.md).


### Current implementation update — 2026-10-14

Browser OIDC code now supports state/nonce-bound PKCE, HTTPS token exchange,
separate RS256 ID/access token verification, Redis-backed opaque HttpOnly
sessions, browser CSRF+Origin checks, analyst/admin RBAC and logout revocation.
Caddy TLS + deployment Compose validation, and Redis-shared global/per-credential
rate limits have CI evidence. Production is fail-closed without OIDC, Redis
and a checksum-pinned trusted model. No real domain, IdP or independent
penetration test has been verified. See [runbook](DEPLOYMENT_SSO_TLS.md)
and [pentest scope](PENETRATION_TEST_HANDOFF.md).

The passive ZAP scan of localhost development found zero fail categories and
nine warning categories, including inline-style CSP and Swagger UI CDN SRI.
Development Swagger is not reachable through the production Caddy gateway.
These are open review items, not evidence of a clean live pentest.
