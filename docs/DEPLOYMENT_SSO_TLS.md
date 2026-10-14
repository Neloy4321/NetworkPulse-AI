# HTTPS / OIDC / Redis security deployment runbook

**State:** Configuration and automated tests exist in the repository. No public
infrastructure, real IdP, domain, TLS certificate or operational model has been
deployed or independently security-tested by this repository workflow.

## Preconditions owned by the operator

1. Configure a hostname such as `soc.example.org` with DNS pointing to the
   permitted server. Allow 80/443 through the firewall; keep host port 8000
   loopback-only. Caddy issues and renews TLS certificates automatically if the
   public hostname resolves and ACME challenges can reach the server.
2. Register a **public OIDC client** with Authorization Code + S256 PKCE,
   exact callback `https://soc.example.org/auth/callback`, and `openid` scope.
   Require an RS256 JWT **access** token with audience `networkpulse-api`,
   issuer equal to the configured issuer, and
   `networkpulse_role` of `viewer`, `analyst` or `admin`.
   The separate RS256 **ID** token must have the public OAuth client ID as its
   audience and echo the transaction nonce; both tokens must identify the
   same subject. Opaque access tokens are not supported.
3. Provision a **trusted, independently validated** `model.joblib` into
   Docker's private `model_data` volume before production startup and
   record its exact SHA-256 in private `MODEL_SHA256`. This requirement is
   intentional: production mode never falls back to synthetic bootstrap.
   Independently validate the model's provenance before unpickling it.
4. Create a private local `.env` (never commit it) containing the values
   below. Generate random hexadecimal credentials locally so characters in
   the Redis URL do not require percent-encoding.

```dotenv
POSTGRES_PASSWORD=<locally-generated-private-random-value>
NETWORKPULSE_API_KEY=<locally-generated-private-random-value>
SECURITY_REDIS_PASSWORD=<locally-generated-private-hexadecimal-value>
MODEL_SHA256=<64-hex-digit-sha256-of-prevalidated-private-model>
NETWORKPULSE_DOMAIN=soc.example.org
NETWORKPULSE_OIDC_ISSUER=https://idp.example.org/realms/soc
NETWORKPULSE_OIDC_AUDIENCE=networkpulse-api
NETWORKPULSE_OIDC_JWKS_URL=https://idp.example.org/realms/soc/protocol/openid-connect/certs
NETWORKPULSE_OIDC_AUTH_URL=https://idp.example.org/realms/soc/protocol/openid-connect/auth
NETWORKPULSE_OIDC_TOKEN_URL=https://idp.example.org/realms/soc/protocol/openid-connect/token
NETWORKPULSE_OIDC_CLIENT_ID=networkpulse-browser
```

The URLs above are **examples**, not a working or verified IdP.

## Build and stage

```bash
docker compose -f compose.yaml -f compose.tls.yaml config -q
docker compose -f compose.yaml -f compose.tls.yaml up -d --build
docker compose -f compose.yaml -f compose.tls.yaml ps
```

The `security-redis` instance uses no RDB snapshots or AOF persistence:
sessions and pending PKCE state disappear upon Redis restart and users must
sign in again. Redis is never bound to a public host port. Its authenticated
connection stays on the private Compose network; host backups must not
unintentionally include Redis memory dumps. Network administrators should
separately enforce host-level segmentation and secret rotation.

The Caddy gateway is pinned to a recent supported release, enforces TLS and
HSTS and limits upload bodies; the backend independently enforces its own
body bounds and a fail-closed Redis sliding-window limiter. The per-credential
rate buckets are shared across replicas and a global quota restricts request
churn. Unknown clients behind one gateway may share a peer-address quota;
an attacker can rotate unverified credentials, so upstream abuse controls and
DDoS protections remain necessary. Never trust client-supplied X-Forwarded-For
values as the source of authorization or application rate limits.

## Browser login and authorization behavior

- `/auth/login` creates a one-use server-side state, nonce and PKCE challenge
  with 5-minute TTL; state cookie is Secure / HttpOnly / SameSite=Lax.
- `/auth/callback` consumes the state, exchanges a code via HTTPS, validates
  RS256 access and ID tokens, nonce and matching subject, then issues only an
  opaque Secure / HttpOnly / SameSite=Lax session cookie. Tokens stay inside
  the Redis security store, not browser localStorage.
- `/auth/session` returns an in-memory CSRF token to the authenticated page.
  Browser-originated POST/PATCH/DELETE must have the CSRF header and exact
  configured HTTPS Origin; external callers may instead supply an authorized
  bearer token. No session is valid longer than 15 minutes or its access JWT.
- `/auth/logout` requires valid CSRF and revokes the Redis session immediately.
  The browser is then redirected to the sign-in flow.
- Viewers can read, Analysts can ingest/triage, Admins can access metrics
  internally. The public Caddy gateway hides `/metrics`, documentation and
  OpenAPI. The local development UI/key behavior is unchanged.

## Required tests before any internet-facing launch

Verify every exact configuration with a staging IdP: normal login/logout,
revocation from a second worker, wrong issuer/audience, unauthorized Analyst
mutation from Viewer, cookie CSRF and Origin refusal, JWKS rotation,
Redis outage, provider timeout, TLS certificate issuance/renewal, network
firewall rules, leaked headers, upload-size limits and data retention.

Automated unit/security CI and
[local passive ZAP](../.github/workflows/authorized-dast.yml) are **not an
independent penetration test**. Obtain a separately authorized, independently
executed test of the actual deployed/staging hostname before public launch.

See [independent pentest handoff](PENETRATION_TEST_HANDOFF.md) and
[security threat model](SECURITY_THREAT_MODEL.md).


## Deploy/release hardening (2026-10-14)

**Required first:** take an independently tested `pg_dump` backup and verify
restore access. Before starting the production API, deliberately migrate the
database using the *same image and configuration* as production:

```bash
docker compose -f compose.yaml -f compose.tls.yaml up -d db security-redis
docker compose -f compose.yaml -f compose.tls.yaml build api
docker compose -f compose.yaml -f compose.tls.yaml run --rm --no-deps api networkpulse db upgrade
docker compose -f compose.yaml -f compose.tls.yaml run --rm --no-deps api networkpulse db check
docker compose -f compose.yaml -f compose.tls.yaml --profile streaming up -d --no-build
docker compose -f compose.yaml -f compose.tls.yaml --profile streaming ps
```

The API now uses **read-only schema validation** (`networkpulse db check`)
on production startup, and explicitly fails if the configured revision is not
current. It does NOT run a concurrent Alembic migration while replicas start.
The development path keeps local automatic migrations and seeded demo training,
but **production startup rejects demo/synthetic model metadata**. This metadata
guard is not a cryptographic signature or independent site validation;
manually verify the trusted joblib artifact, model SHA-256 and operator approval
before loading it. Do not upload an untrusted pickle/joblib.

Behavior and MLOps workers write an atomic successful-cycle heartbeat under
container `/tmp`, evaluated by healthchecks with separate freshness limits
(180 seconds / 900 seconds). A worker crash exits and restarts under Docker
restart policy; a **stalled-but-running container is reported unhealthy**, not
automatically restarted by plain Docker Compose. Configure your host monitoring
to page operators on unhealthy containers and perform controlled restart after
investigation. An MLOps `insufficient_data` cycle can still be healthy as
a *process*; it does not mean the model or traffic is healthy. Independently
alert when required hourly MLOps evidence stops arriving.

The `streaming` profile must be explicitly enabled or the Redis ingest
worker, behavioral correlation worker and MLOps worker will not start.
For a complete operational deployment, additionally validate OIDC/PKCE with
the real IdP, HTTPS/certificate issuance, backups/restore, Redis outages,
high-volume DB performance, hardening, on-call alerts, user permissions and
external penetration test. CI is a deployment configuration/smoke check, not
a proof of live site readiness.
