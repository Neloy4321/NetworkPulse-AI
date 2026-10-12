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

Tokens must be sent as `Authorization: Bearer <OIDC access token>`. Viewer reads; Analyst ingests and triages; Admin accesses `/metrics`. **OIDC mode currently does not offer a browser login/PKCE flow**; an identity provider and credentialed reverse proxy or browser integration are required before publishing a usable multi-user SOC dashboard. Do **not** expose local mode directly to the internet.

## Priority blockers to production

- OIDC browser sign-in/PKCE and per-request actor audit logging.
- TLS reverse proxy, distributed rate limiting, secure cookies and CSP, security test suite.
- Secret rotation, backups encryption, monitoring, vulnerability scans and penetration testing.
- Model artifact integrity verification and rollback protocol.
