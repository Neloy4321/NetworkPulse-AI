# Operations & Responsible Deployment

## Run modes

### Local SQLite (recommended for learning and demos)

```bash
export NETWORKPULSE_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
python -m pip install -e '.[dev]'
networkpulse db upgrade
networkpulse bootstrap
uvicorn networkpulse.api:create_app --factory --host 127.0.0.1 --port 8000
```

The migration command creates or upgrades the database schema before ingestion. It backs up existing SQLite files when a revision change is necessary. A SQLite database and detector artifact are written into ignored `data/` paths. Do not expose this server directly to the internet.

### Docker Compose with PostgreSQL

```bash
cp .env.example .env
# Set random NETWORKPULSE_API_KEY and POSTGRES_PASSWORD
# Then:
docker compose up --build
```

`db` runs PostgreSQL 16; `api` waits for its health check and bootstraps a synthetic demo model if the persisted volume does not yet have one. Application access is bound to **localhost:8000**, not every host interface. Compose secrets are passed as environment variables for local convenience; hosted production should use a secrets manager.

## Migration and database backup

Run `networkpulse db upgrade` **before** `networkpulse bootstrap` or the FastAPI service. For existing local data, back up the SQLite file first, then migrate in place. The migration runbook covers revision checks, legacy DB recognition and recovery: [Database Migrations](DATABASE_MIGRATIONS.md). PostgreSQL must be backed up and tested separately before a production migration.

## Security considerations

- Input validation: IPvAnyAddress, bounded counts, timezone-aware timestamps, strict Pydantic models.
- Mutating endpoints: API key with constant-time comparison; minimum 16 characters on startup.
- Read-only endpoints: intentionally unauthenticated to support local demonstration. **Place behind authentication before exposing remotely.**
- Browser: single-origin static assets and read-only polling; operator key requested per manual triage, never persisted to localStorage.
- Model artifacts: pickle/joblib, trust-boundary sensitive. Do not accept uploaded models.
- Supply-chain: dependencies bounded by major versions, not fully locked. Generate and audit a lockfile before regulated deployments.
- Data sensitivity: event IP addresses may be personal data. Limit access/retention and secure backups.
- Read-only dashboards have no rate limiting; put a gateway in front before remote access.
- Simulated alert severity is a triage convention and cannot auto-block network traffic.

## Data and model lifecycle

- Replaying the same event does not create multiple flow records or alerts in ordinary sequential operation.
- The `bootstrap` CLI reuses the existing model if present. Delete/retrain **only in your own local environment** when you intentionally change the training data or feature contract.
- Back up PostgreSQL and models; keep an external copy of the training inputs, schema and validation results.
- Alembic schema migrations and safe SQLite backup are available, but automated retention, drift monitoring and multi-tenant isolation are not implemented.

## Health checks

| Endpoint | Purpose |
| :--- | :--- |
| `/health/live` | Process is accepting HTTP requests |
| `/health/ready` | Detector loaded and database reachable |
| `/api/v1/model` | Model version, provenance and held-out metrics |

## Failure guide

| Symptom | Likely cause | Action |
| :--- | :--- | :--- |
| `401` on ingest/triage | Missing/incorrect key | Set `NETWORKPULSE_API_KEY`, pass `X-API-Key` header |
| `503` on ingest/readiness | No trusted model artifact | Run `networkpulse bootstrap` or `networkpulse train` |
| Database connection error | Missing SQLite folder/incorrect DSN/Postgres offline | Check `DATABASE_URL`, database volume and credentials |
| No anomalies | Normal data or threshold too conservative | Check `model` endpoint and supply known validation data |
| Many false positives | Baseline mismatch, missing context, source differences | Review inputs and recalibrate using representative benign periods |
| Dashboard cannot load scripts | Wrong root path or reverse proxy | Serve at repository root `/`, keep `/static/{filename}` intact |

## Scalability and future security improvements

This remains a single-service engineering example. Conflict-safe batched inserts and transactional alert creation are implemented in v0.2, but high-throughput validation and PostgreSQL integration tests are **not** complete. Future work includes reliable queues, backpressure, concurrent collector coordination, monitoring, retention/archival automation and tenant-level authorization. See [Database Migrations](DATABASE_MIGRATIONS.md).
