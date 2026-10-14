"""Redis-backed, multi-worker sliding-window request limiter.

One Redis Lua transaction counts both global and per-peer requests using the
Redis server clock. No caller-supplied X-Forwarded-For value is trusted.
"""
from __future__ import annotations

import hashlib
import secrets

from redis.exceptions import RedisError

_SCRIPT = """
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000000 + tonumber(t[2])
local cutoff = now - 60000000
for i=1,2 do
  redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', cutoff)
end
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[1])
   or redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[2]) then
  return 0
end
for i=1,2 do
  redis.call('ZADD', KEYS[i], now, ARGV[3])
  redis.call('EXPIRE', KEYS[i], 61)
end
return 1
"""


class DistributedLimiter:
    """Fail closed when Redis is unavailable; shared between all API replicas."""

    def __init__(self, redis_client, per_minute: int, global_per_minute: int):
        if per_minute < 1 or global_per_minute < per_minute:
            raise ValueError("Invalid distributed rate limits")
        self.redis = redis_client
        self.per_minute = per_minute
        self.global_per_minute = global_per_minute

    def admit(self, peer: str) -> bool:
        digest = hashlib.sha256(peer.encode("utf-8")).hexdigest()
        keys = ["np:ratelimit:global", "np:ratelimit:peer:" + digest]
        try:
            return bool(self.redis.eval(
                _SCRIPT, 2, *keys, self.global_per_minute,
                self.per_minute, secrets.token_hex(16)
            ))
        except RedisError:
            return False
