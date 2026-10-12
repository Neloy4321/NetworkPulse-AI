FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY networkpulse/ ./networkpulse/
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir ".[postgres]" && \
    useradd --create-home --uid 10001 networkpulse && mkdir -p /app/data && chown networkpulse:networkpulse /app/data
USER networkpulse
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready',timeout=4)"
CMD ["sh", "-c", "python -m networkpulse.cli bootstrap && uvicorn networkpulse.api:create_app --factory --host 0.0.0.0 --port 8000"]
