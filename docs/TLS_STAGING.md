# Optional TLS reverse proxy staging example — NOT verified deployment

Use `docker compose -f compose.yaml -f compose.tls.yaml up --build` **only** with DNS and a properly configured real OIDC provider (`NETWORKPULSE_OIDC_ISSUER`, `NETWORKPULSE_OIDC_AUDIENCE`, `NETWORKPULSE_OIDC_JWKS_URL`, and `NETWORKPULSE_DOMAIN`). The Compose override makes `NETWORKPULSE_AUTH_MODE=oidc` mandatory for the externally exposed Caddy reverse proxy. Caddy needs TCP ports 80/443 and a usable public domain/certificate flow; isolate PostgreSQL/Redis.

This configuration is a security-oriented **starting point**, not evidence of passing a penetration test, completed IdP integration, production network isolation, backup/rollback drill, or external hosting. The default frontend currently requires an OIDC token supplied outside the dashboard API; an end-user PKCE login is still required for a fully usable hosted browser experience.
