"""HTTP hardening: request ids, body size limit, rate limiting, security headers."""

import secrets
import threading
import time
from collections import defaultdict

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.config import Settings
from app.errors import error_body


def client_ip(request: Request, settings: Settings) -> str:
    if settings.trust_proxy:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            # Right-most entry is the one our own proxy appended.
            return fwd.split(",")[-1].strip()[:45]
    return request.client.host if request.client else "unknown"


class RateLimiter:
    """Fixed-window counter per (bucket, client).

    In-memory, so it is per process. A multi-instance deployment would keep
    the counters in Redis; the interface stays the same.
    """

    def __init__(self, window_seconds: int = 60) -> None:
        self.window = window_seconds
        self._hits: dict[tuple[str, str, int], int] = defaultdict(int)
        self._lock = threading.Lock()

    def hit(self, bucket: str, key: str, limit: int) -> tuple[bool, int]:
        now = time.time()
        window = int(now // self.window)
        with self._lock:
            if len(self._hits) > 50_000:  # bound memory
                self._hits = defaultdict(int, {k: v for k, v in self._hits.items() if k[2] == window})
            self._hits[(bucket, key, window)] += 1
            count = self._hits[(bucket, key, window)]
        retry_after = int(self.window - (now % self.window)) + 1
        return count <= limit, retry_after

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


SECURITY_HEADERS = {
    # API returns JSON only: nothing may be loaded, framed or executed.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}

AUTH_PATHS = {"/api/v1/auth/login", "/api/v1/auth/refresh"}


def install(app: FastAPI, settings: Settings, limiter: RateLimiter) -> None:
    @app.middleware("http")
    async def hardening(request: Request, call_next):
        request.state.request_id = secrets.token_hex(8)
        request.state.client_ip = client_ip(request, settings)

        def reject(status: int, message: str, headers: dict | None = None):
            resp = JSONResponse(error_body(request, status, message), status_code=status, headers=headers)
            return finish(resp)

        def finish(resp):
            for k, v in SECURITY_HEADERS.items():
                resp.headers.setdefault(k, v)
            if settings.enable_hsts:
                resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
            resp.headers["X-Request-ID"] = request.state.request_id
            return resp

        length = request.headers.get("content-length")
        if length is not None:
            if not length.isdigit():
                return reject(400, "Invalid Content-Length")
            if int(length) > settings.max_body_bytes:
                return reject(413, "Request body too large")

        if settings.rate_limit_enabled:
            ip = request.state.client_ip
            ok, retry = limiter.hit("default", ip, settings.rate_limit_default)
            if ok and request.url.path in AUTH_PATHS:
                ok, retry = limiter.hit("auth", ip, settings.rate_limit_login)
            if not ok:
                return reject(429, "Too many requests", {"Retry-After": str(retry)})

        response = await call_next(request)
        if "server" in response.headers:
            del response.headers["server"]
        return finish(response)
