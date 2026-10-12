"""Run only when an isolated PostgreSQL test database is supplied (CI service)."""

import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import BigInteger, func, inspect, select

from networkpulse.detector import train
from networkpulse.migrations import upgrade_database
from networkpulse.service import ingest
from networkpulse.simulator import sample_flows
from networkpulse.storage import Alert, NetworkEvent, build_sessions


@pytest.mark.skipif(not os.getenv("PG_TEST_DATABASE_URL"), reason="No CI PostgreSQL service")
def test_postgres_migration_bigint_and_upsert_contention():
    url = os.environ["PG_TEST_DATABASE_URL"]
    assert upgrade_database(url)["revision"] == "0003_soc_accountability"
    maker = build_sessions(url)
    engine = maker.kw["bind"]
    try:
        counter_names = ("orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts")
        cols = {c["name"]: c["type"] for c in inspect(engine).get_columns("network_events")}
        assert all(isinstance(cols[name], BigInteger) for name in counter_names)

        samples = sample_flows(145, seed=27)
        detector = train(samples, seed=27)
        flows = samples[110:130]
        flows[0] = flows[0].model_copy(update={"orig_bytes": 9_000_000_000})

        def worker():
            with maker() as session:
                return ingest(session, detector, flows)

        with ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(lambda _: worker(), range(5)))
        assert sum(x["inserted"] for x in results) == len(flows)
        with maker() as session:
            assert session.scalar(select(func.count(NetworkEvent.id))) == len(flows)
            assert session.scalar(select(func.count(Alert.id))) == sum(x["alerts_created"] for x in results)
            assert session.get(NetworkEvent, flows[0].key()).orig_bytes == 9_000_000_000
    finally:
        engine.dispose()
