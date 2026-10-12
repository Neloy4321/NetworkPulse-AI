"""Single-process HTTP mutation rate and request-body limits.

For horizontally scaled deployments, enforce distributed limits at the gateway.
This implementation intentionally does not trust client-controlled forwarded IP headers.
"""
from __future__ import annotations

import threading
import time
from collections import deque

from fastapi import Request
from starlette.responses import JSONResponse


class MutationLimiter:
    def __init__(self, per_minute: int):
        if per_minute < 1:
            raise ValueError('per-minute rate limit must be >= 1')
        self.limit = per_minute
        self.buckets = {}
        self.lock = threading.Lock()

    def admit(self, peer: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self.lock:
            bucket = self.buckets.setdefault(peer, deque())
            while bucket and now - bucket[0] >= 60:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return False
            bucket.append(now)
            # Periodically bound memory for distinct clients.
            if len(self.buckets) > 10000:
                self.buckets = {k: v for k, v in self.buckets.items()
                                if v and now - v[-1] < 60}
            return True


def security_middleware_factory(*, max_body_bytes: int, per_minute: int):
    if max_body_bytes < 1024:
        raise ValueError('MAX_BODY_BYTES must be >= 1024')
    limiter = MutationLimiter(per_minute)

    async def security_middleware(request: Request, call_next):
        if request.method in {'POST', 'PATCH', 'PUT', 'DELETE'}:
            header = request.headers.get('content-length')
            if header:
                try:
                    size = int(header)
                except ValueError:
                    return JSONResponse({'detail': 'Invalid Content-Length'}, status_code=400)
                if size > max_body_bytes or size < 0:
                    return JSONResponse({'detail': 'Request body too large'}, status_code=413)
            # Header-less/chunked messages are enforced while streaming, not after
            # unlimited buffering. Starlette's request receive channel is repopulated
            # with one validated body for downstream FastAPI/Pydantic processing.
            buf = bytearray()
            async for piece in request.stream():
                buf.extend(piece)
                if len(buf) > max_body_bytes:
                    return JSONResponse({'detail': 'Request body too large'}, status_code=413)
            # Starlette BaseHTTPMiddleware's cached request uses _body when
            # constructing downstream receive messages. The streaming check above
            # prevents allocating a body larger than the configured cap.
            request._body = bytes(buf)
            peer = request.client.host if request.client else 'unknown'
            if not limiter.admit(peer):
                return JSONResponse({'detail': 'Mutation rate limit exceeded'}, status_code=429,
                                    headers={'Retry-After': '60'})
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Frame-Options'] = 'DENY'
        return response

    return security_middleware
