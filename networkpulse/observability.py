"""HTTP and model-process observability without leaking addresses or tokens."""

from __future__ import annotations

import json
import logging
import time
import uuid

from fastapi import Request
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.responses import Response

HTTP_REQUESTS = Counter("networkpulse_http_requests_total", "API HTTP requests", ["route", "method", "status"])
HTTP_LATENCY = Histogram("networkpulse_http_request_seconds", "Request latency in seconds", ["route", "method"], buckets=(.002, .01, .025, .05, .1, .25, .5, 1, 2, 5, 10))
INGEST_TOTAL = Counter("networkpulse_flow_ingest_total", "Flows accepted by server", ["result"])
ALERT_ACTIONS = Counter("networkpulse_alert_updates_total", "Status update operations", ["status"])
MODEL_INFERENCE = Histogram("networkpulse_model_scoring_seconds", "Detector scoring time in seconds", buckets=(.001,.005,.01,.05,.1,.5,1,3,10))
logger = logging.getLogger("networkpulse.access")


async def metric_middleware(request: Request, call_next):
    started = time.perf_counter()
    request_id = request.headers.get("x-request-id", "")
    if not request_id or len(request_id) > 64 or not request_id.isascii() or not request_id.isprintable():
        request_id = uuid.uuid4().hex
    code = 500
    try:
        response = await call_next(request)
        code = response.status_code
        response.headers["X-Request-ID"] = request_id
        return response
    finally:
        # Static routes have bounded labels. Request URLs (IPs and tokens) are never labels.
        route = request.scope.get("route")
        label = getattr(route, "path", "unmatched")
        elapsed = time.perf_counter() - started
        HTTP_REQUESTS.labels(label, request.method, str(code)).inc()
        HTTP_LATENCY.labels(label, request.method).observe(elapsed)
        logger.info(json.dumps({"message": "http_request", "request_id": request_id,
                                "route": label, "method": request.method,
                                "status": code, "duration_ms": round(elapsed * 1000, 2)}))


def exporter() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
