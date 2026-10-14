# Multi-stage local/staging image. Pin base-image digests for audited production releases.
FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1
WORKDIR /build
COPY pyproject.toml README.md ./
COPY networkpulse/ ./networkpulse/
COPY alembic.ini ./
COPY alembic/ ./alembic/
RUN python -m venv /opt/networkpulse-venv && \
    /opt/networkpulse-venv/bin/pip install --no-cache-dir '.[postgres,streaming]'

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PATH="/opt/networkpulse-venv/bin:$PATH"
WORKDIR /app
COPY --from=builder /opt/networkpulse-venv /opt/networkpulse-venv
COPY networkpulse/ ./networkpulse/
COPY alembic.ini ./
COPY alembic/ ./alembic/
RUN groupadd --system --gid 10001 networkpulse && \
    useradd --system --uid 10001 --gid networkpulse --home-dir /app networkpulse && \
    mkdir -p /app/data && chown -R networkpulse:networkpulse /app/data
USER networkpulse
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready',timeout=4)"
# Production never mutates DB schema on API startup. An operator runs the
# migration against a verified backup, then the API checks the revision.
CMD ["sh", "-ec", "if [ \"${NETWORKPULSE_DEPLOYMENT:-development}\" = production ]; then python -m networkpulse.cli db check; test -s /app/data/model.joblib || { echo \"Production requires a prevalidated model\"; exit 1; }; test -n \"${MODEL_SHA256:-}\" || { echo \"Production requires MODEL_SHA256\"; exit 1; }; else python -m networkpulse.cli db upgrade; python -m networkpulse.cli bootstrap; fi; exec uvicorn networkpulse.api:create_app --factory --host 0.0.0.0 --port 8000 --no-access-log"]
