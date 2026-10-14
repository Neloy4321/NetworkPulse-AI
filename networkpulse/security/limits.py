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
    """Bounded single-process admission control; never trust forwarded IPs."""

    def __init__(self, per_minute: int, max_peers: int = 10000):
        if per_minute < 1 or not 10 <= max_peers <= 100000:
            raise ValueError('invalid mutation rate or peer capacity')
        self.limit = per_minute
        self.max_peers = max_peers
        self.buckets = {}
        self.lock = threading.Lock()

    def admit(self, peer: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self.lock:
            bucket = self.buckets.get(peer)
            if bucket is None:
                if len(self.buckets) >= self.max_peers:
                    # Reclaim inactive peers before refusing new peers. Never
                    # evict active buckets: that resets their rate-limit debt.
                    for key, values in list(self.buckets.items()):
                        if not values or now - values[-1] >= 60:
                            del self.buckets[key]
                    if len(self.buckets) >= self.max_peers:
                        return False
                bucket = deque()
                self.buckets[peer] = bucket
            while bucket and now - bucket[0] >= 60:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return False
            bucket.append(now)
            return True


def security_middleware_factory(*, max_body_bytes: int, per_minute: int,
                                distributed_limiter=None):
    """Security policy for HTTP resources, including early rejected responses."""
    if max_body_bytes < 1024:
        raise ValueError('MAX_BODY_BYTES must be >= 1024')
    limiter = MutationLimiter(per_minute)

    def protect_headers(response, *, https: bool, path: str):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
        if https:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        if path not in {'/docs', '/redoc'} and not path.startswith('/docs/'):
            response.headers['Content-Security-Policy'] = (
                "default-src 'self'; base-uri 'none'; object-src 'none'; "
                "frame-ancestors 'none'; form-action 'self'; "
                "script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "connect-src 'self'; img-src 'self' data:"
            )
        if (path == '/' or path.startswith('/api/') or path.startswith('/auth/')
                or path == '/metrics'):
            response.headers['Cache-Control'] = 'no-store'
        return response

    async def security_middleware(request: Request, call_next):
        def rejected(detail: str, status: int, headers=None):
            return protect_headers(
                JSONResponse({'detail': detail}, status_code=status, headers=headers),
                https=request.url.scheme == 'https', path=request.url.path
            )
        if request.method in {'POST', 'PATCH', 'PUT', 'DELETE'}:
            header = request.headers.get('content-length')
            if header:
                try:
                    size = int(header)
                except ValueError:
                    return rejected('Invalid Content-Length', 400)
                if size > max_body_bytes or size < 0:
                    return rejected('Request body too large', 413)
            # Admit before reading a potentially expensive chunked body. A
            # known oversize Content-Length was already rejected without charge.
            peer = request.client.host if request.client else 'unknown'
            # Credential-bound buckets avoid placing all users behind Caddy
            # into one shared quota. A global Redis budget remains mandatory:
            # unverified arbitrary credentials could otherwise evade a peer cap.
            credential = (request.headers.get("authorization") or
                          request.cookies.get("__Host-np-session"))
            if distributed_limiter is not None and credential and 16 <= len(credential) <= 8192:
                peer = "credential:" + credential
            allowed = (distributed_limiter.admit(peer) if distributed_limiter is not None
                       else limiter.admit(peer))
            if not allowed:
                return rejected('Mutation rate limit exceeded', 429,
                                {'Retry-After': '60'})
            # Header-less/chunked messages are enforced while streaming, not after
            # unlimited buffering. Starlette's request receive channel is repopulated
            # with one validated body for downstream FastAPI/Pydantic processing.
            buf = bytearray()
            async for piece in request.stream():
                buf.extend(piece)
                if len(buf) > max_body_bytes:
                    return rejected('Request body too large', 413)
            # Starlette BaseHTTPMiddleware's cached request uses _body when
            # constructing downstream receive messages. The streaming check above
            # prevents allocating a body larger than the configured cap.
            request._body = bytes(buf)
        response = await call_next(request)
        return protect_headers(
            response, https=request.url.scheme == 'https', path=request.url.path
        )

    return security_middleware
