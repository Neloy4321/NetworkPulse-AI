"""Isolated Stage B synthetic event integrity and load measurement.

Never imports or initializes a model, classifier, production ingest API, or
production database schema. This is a controlled non-ML CI/staging exerciser,
not an IDS throughput benchmark or operational acceptance certificate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import time
import uuid
from dataclasses import dataclass

import psycopg
import redis

from networkpulse.infra_staging import DATABASE_NAME, STAGING_MODE
from networkpulse.streaming.redis_streams import BackpressureError, FlowStream

DB_USER = "networkpulse_staging"
CONFIRM = "I_ACCEPT_ISOLATED_SYNTHETIC_STAGE_B"
KIND = "networkpulse-stage-b-synthetic-v1"
TABLE = "np_stage_b_synthetic_receipts"


@dataclass(frozen=True)
class LabSettings:
    db_host: str
    db_port: int
    db_password: str
    redis_host: str
    redis_port: int
    redis_password: str

    @classmethod
    def from_env(cls) -> LabSettings:
        if os.getenv("NETWORKPULSE_STAGING_MODE") != STAGING_MODE:
            raise ValueError("Stage B requires isolated non-ML staging mode")
        if os.getenv("NETWORKPULSE_STAGE_B_CONFIRM") != CONFIRM:
            raise ValueError("Explicit isolated synthetic test consent required")
        if os.getenv("NETWORKPULSE_STAGING_DB_NAME", DATABASE_NAME) != DATABASE_NAME:
            raise ValueError("Stage B refuses a non-staging database")
        secrets = []
        for name in ("NETWORKPULSE_STAGING_DB_PASSWORD",
                     "NETWORKPULSE_STAGING_REDIS_PASSWORD"):
            value = os.getenv(name, "")
            if len(value) < 20 or value != value.strip() or value.lower().startswith(
                ("changeme", "password", "replace-me", "example")
            ):
                raise ValueError(f"{name} requires a dedicated non-placeholder secret")
            secrets.append(value)
        hosts = [
            os.getenv("NETWORKPULSE_STAGING_DB_HOST", "db"),
            os.getenv("NETWORKPULSE_STAGING_REDIS_HOST", "redis"),
        ]
        if any(not re.fullmatch(r"[a-zA-Z0-9._-]{1,253}", host) for host in hosts):
            raise ValueError("Invalid private dependency hostname")
        ports = [int(os.getenv("NETWORKPULSE_STAGING_DB_PORT", "5432")),
                 int(os.getenv("NETWORKPULSE_STAGING_REDIS_PORT", "6379"))]
        if any(not 1 <= port <= 65535 for port in ports):
            raise ValueError("Invalid dependency port")
        return cls(hosts[0], ports[0], secrets[0], hosts[1], ports[1], secrets[1])

    def connect(self):
        pg = psycopg.connect(
            host=self.db_host, port=self.db_port, dbname=DATABASE_NAME,
            user=DB_USER, password=self.db_password, connect_timeout=5,
            autocommit=True,
        )
        try:
            cache = redis.Redis(
                host=self.redis_host, port=self.redis_port,
                password=self.redis_password, decode_responses=True,
                socket_connect_timeout=5, socket_timeout=5,
                retry_on_timeout=False,
            )
            cache.ping()
            return pg, cache
        except BaseException:
            pg.close()
            raise


def _digest(payload: dict) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _percentile(numbers: list[float], percentage: int) -> float | None:
    if not numbers:
        return None
    sorted_values = sorted(numbers)
    index = max(0, math.ceil(len(sorted_values) * percentage / 100) - 1)
    return round(sorted_values[index], 3)


class SyntheticIntegrityHarness:
    """One test run, namespaced Redis stream, dedicated staging PostgreSQL table.

    Queue delivery is at-least-once. Uniqueness and payload-digest checks make
    DB effects idempotent. Redis ACK only occurs after PostgreSQL commit.
    """

    def __init__(self, pg, cache, *, run_id: str | None = None, max_backlog: int = 100):
        self.pg = pg
        self.cache = cache
        self.run_id = run_id or uuid.uuid4().hex
        if not re.fullmatch(r"[0-9a-f]{32}", self.run_id):
            raise ValueError("run_id must be a lowercase UUID4-style hex string")
        if not 100 <= max_backlog <= 10000:
            raise ValueError("max_backlog must be between 100 and 10000")
        self._verify_db_identity()
        self.stream = f"networkpulse:stage-b:synthetic:{self.run_id}"
        self.queue = FlowStream(
            cache, stream=self.stream, group="stage-b-workers",
            max_backlog=max_backlog,
        )
        self.expected: dict[str, str] = {}
        self.sent_ns: dict[str, int] = {}
        self.latencies_ms: list[float] = []
        self.inserted = 0
        self.duplicate_effects_prevented = 0
        self.delivery_receipts = 0
        self.backpressure_count = 0
        self.queue.initialize()

    def _verify_db_identity(self):
        with self.pg.cursor() as cursor:
            cursor.execute("SELECT current_database(), current_user")
            name, user = cursor.fetchone()
        if (name, user) != (DATABASE_NAME, DB_USER):
            raise ValueError("Stage B refuses non-isolated PostgreSQL identity")

    def initialize_table(self):
        # Table is restricted to the dedicated Stage A infrastructure database.
        with self.pg.transaction():
            with self.pg.cursor() as cursor:
                cursor.execute(
                    f"CREATE TABLE IF NOT EXISTS {TABLE} ("
                    "run_id text NOT NULL, event_id text NOT NULL, "
                    "ordinal integer NOT NULL, payload_sha256 text NOT NULL, "
                    "PRIMARY KEY (run_id, event_id))"
                )

    def _event(self, ordinal: int) -> dict:
        if not 0 <= ordinal < 100000:
            raise ValueError("invalid synthetic ordinal")
        return {
            "kind": KIND, "run_id": self.run_id,
            "event_id": f"{self.run_id}:{ordinal:06d}", "ordinal": ordinal,
        }

    def _validate(self, payload: dict) -> dict:
        if not isinstance(payload, dict) or set(payload) != {
            "kind", "run_id", "event_id", "ordinal"
        }:
            raise ValueError("Unexpected synthetic event shape")
        ordinal = payload["ordinal"]
        if type(ordinal) is not int or payload != self._event(ordinal):
            raise ValueError("Non-canonical or foreign-run synthetic event")
        return payload

    def enqueue(self, ordinal: int) -> str:
        event = self._event(ordinal)
        event_id = event["event_id"]
        if event_id in self.expected:
            raise ValueError("Each input ordinal may be accepted only once")
        receipt = self.queue.enqueue(event)
        self.expected[event_id] = _digest(event)
        self.sent_ns[event_id] = time.perf_counter_ns()
        return receipt

    def _persist(self, batch: list[dict]):
        inserted = duplicates = 0
        with self.pg.transaction():
            with self.pg.cursor() as cursor:
                for payload in batch:
                    valid = self._validate(payload)
                    digest = _digest(valid)
                    cursor.execute(
                        f"INSERT INTO {TABLE} (run_id, event_id, ordinal, payload_sha256) "
                        "VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING "
                        "RETURNING event_id",
                        (self.run_id, valid["event_id"], valid["ordinal"], digest),
                    )
                    if cursor.fetchone():
                        inserted += 1
                    else:
                        cursor.execute(
                            f"SELECT payload_sha256 FROM {TABLE} "
                            "WHERE run_id=%s AND event_id=%s",
                            (self.run_id, valid["event_id"]),
                        )
                        row = cursor.fetchone()
                        if row is None or row[0] != digest:
                            raise RuntimeError("Synthetic event ID collision or payload mismatch")
                        duplicates += 1
        # Advance counters only after the entire DB transaction commits.
        self.inserted += inserted
        self.duplicate_effects_prevented += duplicates

    def process_once(self, *, consumer: str = "stage-b-worker") -> dict:
        committed: list[dict] = []

        def save(batch):
            self._persist(batch)
            committed.extend(batch)

        result = self.queue.consume_batch_once(
            consumer, save, self._validate, recover=True,
            recover_idle_ms=0, block_ms=5,
        )
        if result["dead_lettered"] or result["retried"]:
            raise RuntimeError("Stage B cannot claim success with pending failed deliveries")
        if result["processed"] != len(committed):
            raise RuntimeError("Stage B committed/delivery accounting mismatch")
        now = time.perf_counter_ns()
        for event in committed:
            started = self.sent_ns.get(event["event_id"])
            if started is not None:
                self.latencies_ms.append((now - started) / 1_000_000)
        self.delivery_receipts += result["processed"]
        return result

    def drain(self, *, max_rounds: int = 1000) -> int:
        processed = 0
        for _ in range(max_rounds):
            if self.cache.xlen(self.stream) == 0:
                break
            receipt = self.process_once()
            if receipt["processed"] == 0:
                raise RuntimeError("Stage B backlog cannot make forward progress")
            processed += receipt["processed"]
        else:
            raise RuntimeError("Stage B exceeded bounded drain rounds")
        return processed

    def reconcile(self) -> dict:
        with self.pg.cursor() as cursor:
            cursor.execute(
                f"SELECT event_id, ordinal, payload_sha256 FROM {TABLE} "
                "WHERE run_id=%s ORDER BY ordinal", (self.run_id,),
            )
            rows = cursor.fetchall()
        observed = {item[0]: item[2] for item in rows}
        stream_depth = self.cache.xlen(self.stream)
        pending = self.cache.xpending(self.stream, self.queue.group)["pending"]
        identity_ok = all(
            event_id == f"{self.run_id}:{ordinal:06d}" for event_id, ordinal, _ in rows
        )
        intact = (
            identity_ok and observed == self.expected and
            len(rows) == len(self.expected) and
            stream_depth == 0 and pending == 0
        )
        return {
            "reconciled": intact, "accepted_unique": len(self.expected),
            "db_unique": len(rows), "db_inserted_this_process": self.inserted,
            "duplicate_effects_prevented": self.duplicate_effects_prevented,
            "acknowledged_deliveries": self.delivery_receipts,
            "redis_stream_depth": stream_depth, "redis_pending": pending,
            "backpressure_events": self.backpressure_count,
        }

    def run(self, events: int) -> dict:
        if not 1 <= events <= 5000:
            raise ValueError("Controlled CI load must be 1..5000 synthetic events")
        self.initialize_table()
        begin = time.perf_counter()
        for number in range(events):
            for _ in range(100):
                try:
                    self.enqueue(number)
                    break
                except BackpressureError:
                    self.backpressure_count += 1
                    if not self.process_once()["processed"]:
                        raise RuntimeError("Backpressure could not be relieved")
            else:
                raise RuntimeError("Stage B bounded enqueue retries exhausted")
        self.drain()
        report = self.reconcile()
        if not report["reconciled"]:
            raise RuntimeError("Stage B integrity reconciliation failed closed")
        elapsed = max(time.perf_counter() - begin, 1e-9)
        return {
            "scope": "ISOLATED_CI_OR_AUTHORIZED_STAGING_NON_ML_ONLY",
            "operational_acceptance": "NOT_CLAIMED",
            "run_id": self.run_id,
            "duration_seconds": round(elapsed, 3),
            "throughput_events_per_second": round(events / elapsed, 2),
            "end_to_end_p95_ms": _percentile(self.latencies_ms, 95),
            "end_to_end_p99_ms": _percentile(self.latencies_ms, 99),
            "latency_sample_count": len(self.latencies_ms),
            **report,
        }

    def cleanup_synthetic_run(self):
        """Explicit test-only cleanup; never modifies the product's data."""
        with self.pg.transaction():
            with self.pg.cursor() as cursor:
                cursor.execute(
                    f"DELETE FROM {TABLE} WHERE run_id=%s", (self.run_id,),
                )
        self.cache.delete(self.stream, self.queue.dead_letter)


def main():
    parser = argparse.ArgumentParser(description="Non-ML isolated Stage B integrity load")
    parser.add_argument("--events", type=int, default=300)
    parser.add_argument("--max-backlog", type=int, default=100)
    parser.add_argument("--cleanup", action="store_true",
                        help="Remove only this run's synthetic receipts and stream")
    args = parser.parse_args()
    settings = LabSettings.from_env()
    pg, cache = settings.connect()
    try:
        harness = SyntheticIntegrityHarness(pg, cache, max_backlog=args.max_backlog)
        try:
            report = harness.run(args.events)
            print(json.dumps(report, sort_keys=True))
        finally:
            if args.cleanup:
                harness.cleanup_synthetic_run()
    finally:
        pg.close()
        cache.close()


if __name__ == "__main__":
    main()
