# NetworkPulse-AI — Stage A Non-ML Secure Staging

**Scope:** secure infrastructure-only staging; not detection, model accuracy or ML acceptance.

## Engineering scope
The separate staging app verifies real PostgreSQL/Redis, OIDC bearer-token RBAC
and private Prometheus metrics. It has no Detector, ML model, flow ingestion,
production API fallback, or product data endpoints. Do not combine the
staging Compose file with the existing real-product Compose files.

GitHub CI must test code, Caddy syntax, Prometheus config, rootless Docker
image build, and **ephemeral real PostgreSQL/Redis integration**. CI intentionally
uses synthetic/invalid OIDC endpoints: it does NOT prove real OIDC sign-in,
real HTTPS certificates, uptime or an independent external deployment.

## Operator-only requirements
- A controlled staging VPS/host, Docker Compose, inbound ports 80/443 and
  outbound HTTPS to the genuine OIDC IdP.
- A dedicated DNS name; valid ACME/public TLS on that hostname.
- Real HTTPS OIDC issuer and JWKS, staging-specific audience, three roles:
  viewer, analyst and admin.
- Strong separately stored PostgreSQL and Redis staging passwords (20+ chars).
  Use secure operator environment/secret management; never put secrets in Git.
- Independent approval that the test host and state are isolated from production.

## Required operator environment variables
- NETWORKPULSE_STAGING_DOMAIN
- NETWORKPULSE_STAGING_DB_PASSWORD
- NETWORKPULSE_STAGING_REDIS_PASSWORD
- NETWORKPULSE_STAGING_OIDC_ISSUER
- NETWORKPULSE_STAGING_OIDC_JWKS_URL
- NETWORKPULSE_STAGING_OIDC_AUDIENCE
- NETWORKPULSE_STAGING_OIDC_ROLE_CLAIM (optional; default networkpulse_role)

Execute from the repository root, after securing real credentials on the host:

    docker compose -f deploy/compose.infra-staging.yml config --quiet
    docker compose -f deploy/compose.infra-staging.yml up -d --build
    docker compose -f deploy/compose.infra-staging.yml ps

Only Caddy may publish 80/443. PostgreSQL, Redis, the staging API, and
Prometheus must NOT have public host ports. Public gateway denies
/internal/*, /metrics, /api/v1/*, /api/v2/*, /docs and OpenAPI routes.
The health/readiness and /api/staging/viewer, /analyst, /admin endpoints
are explicitly marked NON-ML infrastructure-only.

## Actual staging acceptance evidence — NOT established by CI
1. Independently verify public DNS/TLS SAN, chain, expiry and redirect,
   including rejection of invalid hostname and expired certificate.
2. Use real IdP-issued viewer/analyst/admin tokens, check issuer, audience,
   expiry, role-denial, revoked/rotated JWKS key and logout/session behavior.
   This API is bearer-based; browser PKCE remains an additional Stage A task.
3. Demonstrate healthy PostgreSQL/Redis return HTTP 200 readiness; a real
   dependency outage returns HTTP 503, with no leaked credentials.
4. Verify private metrics cannot be downloaded through public Caddy.
5. Preserve actual server resource/health metrics, operator details,
   DNS/TLS reports and signed external review.

## Next stages
Browser OIDC/PKCE login/logout, real infrastructure-only load harness,
worker/Redis/PostgreSQL failure reconciliation, encrypted scheduled offsite
backup, Alertmanager notification, authorized DAST, release/rollback drill,
24–72-hour controlled soak and independent security review.

This is an **implementation milestone**, NOT actual Stage A 7/10,
Stage B 8/10, Stage C 8.5/10 or full NetworkPulse production acceptance.
The existing main product Detector and ML acceptance remain unchanged.
