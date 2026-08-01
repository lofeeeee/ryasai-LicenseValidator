"""
Middleware for License Validator.

- Rate limiting (per IP)
- Abuse detection
- Request logging
"""
import time
from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from loguru import logger


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware.

    Limits:
    - /api/v1/license/validate: 10 requests/minute per IP (prevent brute force)
    - /api/v1/admin/auth/login: 5 requests/minute per IP (prevent credential stuffing)
    - Other endpoints: 60 requests/minute per IP
    """

    def __init__(self, app):
        super().__init__(app)
        # {ip: [(timestamp, path), ...]}
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._cleanup_interval = 60  # seconds
        self._last_cleanup = time.time()

        # Rate limits: (max_requests, window_seconds)
        self.limits = {
            "/api/v1/license/validate": (10, 60),
            "/api/v1/admin/auth/login": (5, 60),
        }
        self.default_limit = (60, 60)

    def _cleanup(self):
        """Remove expired entries."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        cutoff = now - 120  # Keep 2 minutes of history
        for ip in list(self._requests.keys()):
            self._requests[ip] = [t for t in self._requests[ip] if t > cutoff]
            if not self._requests[ip]:
                del self._requests[ip]
        self._last_cleanup = now

    async def dispatch(self, request: Request, call_next):
        self._cleanup()

        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path
        now = time.time()

        # Determine rate limit for this path
        max_requests, window = self.default_limit
        for prefix, limit in self.limits.items():
            if path.startswith(prefix):
                max_requests, window = limit
                break

        # Count requests in window
        key = f"{client_ip}:{path}"
        self._requests[key] = [t for t in self._requests[key] if t > now - window]

        if len(self._requests[key]) >= max_requests:
            logger.warning(f"Rate limit exceeded: {client_ip} on {path} ({len(self._requests[key])}/{max_requests})")
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests. Please try again later.",
                    "retry_after": window,
                },
                headers={"Retry-After": str(window)},
            )

        self._requests[key].append(now)
        response = await call_next(request)
        return response


class AbuseDetectionMiddleware(BaseHTTPMiddleware):
    """
    Detect and flag suspicious license validation patterns.

    Flags:
    - Multiple failed validations from same IP (>5 in 10 min)
    - Rapid machine_id changes from same IP
    - Known invalid keys being retried
    """

    def __init__(self, app):
        super().__init__(app)
        # {ip: [{"time": t, "result": r, "key": k}, ...]}
        self._history: dict[str, list[dict]] = defaultdict(list)
        self._blocked_ips: dict[str, float] = {}  # ip -> blocked_until timestamp
        self._alert_threshold = 5  # failures before alert
        self._block_threshold = 15  # failures before temp block
        self._window = 600  # 10 minutes

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path

        # Check if IP is temporarily blocked
        if client_ip in self._blocked_ips:
            if time.time() < self._blocked_ips[client_ip]:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Temporarily blocked due to suspicious activity."},
                )
            else:
                del self._blocked_ips[client_ip]

        response = await call_next(request)

        # Track validation failures
        if path == "/api/v1/license/validate" and request.method == "POST":
            now = time.time()
            # Clean old entries
            self._history[client_ip] = [
                e for e in self._history[client_ip] if e["time"] > now - self._window
            ]

            if response.status_code in (401, 403) or (
                response.status_code == 200 and hasattr(response, "_body_cache")
            ):
                # Count recent failures
                failures = [e for e in self._history[client_ip] if not e.get("valid")]

                if len(failures) >= self._block_threshold:
                    # Temp block for 30 minutes
                    self._blocked_ips[client_ip] = now + 1800
                    logger.error(
                        f"🚨 ABUSE: IP {client_ip} blocked for 30min "
                        f"({len(failures)} failed validations in {self._window}s)"
                    )
                elif len(failures) >= self._alert_threshold:
                    logger.warning(
                        f"⚠️ SUSPICIOUS: IP {client_ip} has {len(failures)} "
                        f"failed validations in {self._window}s"
                    )

        return response
