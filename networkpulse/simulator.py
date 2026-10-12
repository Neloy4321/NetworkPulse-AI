"""Reproducible flow-metadata simulator for demos/tests only (not a real IDS benchmark)."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from networkpulse.schemas import FlowEvent

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def sample_flows(
    count: int = 1300,
    seed: int = 42,
    start: datetime = BASE,
    anomaly_fraction: float = 0.16,
    safe_prefix_fraction: float = 0.75,
) -> list[FlowEvent]:
    """Inject labeled synthetic outliers only in the later time window.

    Train and calibrate on earlier benign flows; evaluate on chronological holdout.
    This prevents intentional attack labels from entering the unsupervised fit.
    """
    if count < 100 or not 0 <= anomaly_fraction <= 0.5 or not 0.5 <= safe_prefix_fraction <= 0.9:
        raise ValueError("invalid simulator settings")
    rng = random.Random(seed)
    ports = [53, 80, 123, 443, 22, 5432, 3306, 8080, 8443]
    events = []
    for i in range(count):
        outlier = i >= int(count * safe_prefix_fraction) and rng.random() < anomaly_fraction
        source_index = rng.randint(1, 180)
        if outlier:
            port = rng.choice([2323, 31337, 44444, 65000, 23, 3389, 5555])
            dur = round(rng.uniform(0.001, 0.08), 5)
            sent = rng.randint(12, 170)
            recv = 0
            psent, precv = 1, 0
            state = "s0"
        else:
            port = rng.choices(ports, weights=[17, 9, 3, 40, 5, 5, 3, 12, 6])[0]
            dur = round(rng.uniform(0.10, 14), 4)
            sent = rng.randint(140, 12000)
            recv = rng.randint(100, 48000)
            psent, precv = rng.randint(3, 45), rng.randint(2, 72)
            state = rng.choices(["sf", "rej", "s0"], weights=[92, 5, 3])[0]
        evt = FlowEvent(
            timestamp=start + timedelta(seconds=i * 12),
            source="simulator",
            uid=f"demo-{seed}-{i}",
            src_ip=f"10.11.{source_index // 256}.{source_index % 256}",
            dst_ip=f"172.17.{(i * 17) % 254 + 1}.{(i * 7) % 254 + 1}",
            src_port=rng.randint(1024, 65000),
            dst_port=port,
            proto="tcp" if port != 53 else "udp",
            duration=dur,
            orig_bytes=sent,
            resp_bytes=recv,
            orig_pkts=psent,
            resp_pkts=precv,
            conn_state=state,
            label="anomaly" if outlier else "benign",
        )
        events.append(evt)
    return events
