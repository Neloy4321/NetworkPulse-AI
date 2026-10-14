"""Bounded-cardinality stream-worker service level indicators.

The worker exporter is deliberately separate from the API process. The worker
serves only on its private container network; it must never publish this port
to a public interface. Histograms measure Redis enqueue-to-ACK residence and
worker batch call duration, NOT packet-capture-to-alert time.
"""
from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, start_http_server

PROCESSING_SECONDS = Histogram(
    "networkpulse_worker_batch_processing_seconds",
    "Duration of a Redis receive/validate/model/SQL commit/ACK cycle with activity",
    buckets=(.005, .01, .025, .05, .1, .25, .5, 1, 2, 5, 10, 30, 60),
)
QUEUE_RESIDENCE_SECONDS = Histogram(
    "networkpulse_worker_queue_residence_seconds",
    "Age in Redis of each successfully acknowledged flow at ACK completion",
    buckets=(.01, .05, .1, .25, .5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600),
)
COMMITTED_FLOWS = Counter(
    "networkpulse_worker_committed_flows_total",
    "Redis delivery acknowledgements after completed database commits",
)
FAILED_DELIVERIES = Counter(
    "networkpulse_worker_failed_deliveries_total",
    "Valid deliveries left pending after scoring/database handler failure",
)
DEAD_LETTERED = Counter(
    "networkpulse_worker_dead_lettered_total",
    "Permanently invalid deliveries atomically transferred to DLQ",
)
HANDLER_FAILURES = Counter(
    "networkpulse_worker_handler_failures_total",
    "Scoring/transaction handler failures; no payload or exception labels",
)
WORKER_READY = Gauge(
    "networkpulse_worker_healthy",
    "Worker has a verified healthy cycle and no outstanding handler failure (1=yes)",
)


def start_private_exporter(port: int) -> None:
    """Enable per-process telemetry on the private service network only."""
    if not 1024 <= port <= 65535:
        raise ValueError("Worker metrics port must be between 1024 and 65535")
    start_http_server(port, addr="0.0.0.0")


def record_acknowledged(client, message_ids: list[str]) -> None:
    """Metrics are non-critical: call only *after* successful XACK/XDEL.

    Redis TIME and Redis stream-generated IDs use the same clock, avoiding
    host-clock skew. IDs are parsed but never logged or used as labels.
    """
    seconds, microseconds = client.time()
    server_millis = int(seconds) * 1000 + int(microseconds) // 1000
    for identifier in message_ids:
        if isinstance(identifier, bytes):
            identifier = identifier.decode("ascii")
        published_millis = int(identifier.split("-", 1)[0])
        QUEUE_RESIDENCE_SECONDS.observe(
            max(0., (server_millis - published_millis) / 1000.)
        )


def record_cycle(outcome: dict, duration: float) -> None:
    if any(outcome.values()):
        PROCESSING_SECONDS.observe(max(0., duration))
    if outcome["processed"]:
        COMMITTED_FLOWS.inc(outcome["processed"])
    if outcome["retried"]:
        FAILED_DELIVERIES.inc(outcome["retried"])
    if outcome["dead_lettered"]:
        DEAD_LETTERED.inc(outcome["dead_lettered"])
