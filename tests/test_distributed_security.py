"""Redis sliding-window tests; no external network scanning."""
import os

import pytest
from redis.exceptions import ConnectionError

from networkpulse.security.distributed_limit import DistributedLimiter


def test_fail_closed_without_redis():
    class DownRedis:
        def eval(self, *args):
            raise ConnectionError("unreachable")

    limiter = DistributedLimiter(DownRedis(), per_minute=2, global_per_minute=3)
    assert not limiter.admit("operator-a")


def test_reject_invalid_global_budget():
    with pytest.raises(ValueError):
        DistributedLimiter(object(), per_minute=20, global_per_minute=10)


@pytest.mark.skipif(not os.getenv("REDIS_TEST_URL"), reason="Requires CI Redis")
def test_shared_redis_limits_across_instances():
    import redis

    r = redis.Redis.from_url(os.environ["REDIS_TEST_URL"])
    for key in r.scan_iter("np:ratelimit:*"):
        r.delete(key)
    first = DistributedLimiter(r, per_minute=2, global_per_minute=3)
    second = DistributedLimiter(r, per_minute=2, global_per_minute=3)
    try:
        assert first.admit("operator-a")
        assert second.admit("operator-a")
        assert not first.admit("operator-a")
        assert second.admit("operator-b")
        assert not first.admit("operator-b")
        assert not second.admit("operator-c")
    finally:
        for key in r.scan_iter("np:ratelimit:*"):
            r.delete(key)
        r.close()
