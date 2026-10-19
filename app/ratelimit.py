"""Simple per-client rate limiting (OWASP API4: unrestricted resource consumption).

Fixed one-minute windows, kept in memory. Good enough for one instance; a real
deployment would put this in the API gateway or a shared store like Redis.
Remaining quota is exposed on every response via RateLimit-* headers.
"""

from __future__ import annotations

import threading
import time

from fastapi import Request

from .config import get_settings
from .errors import APIError


class FixedWindowLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._windows: dict[str, tuple[int, int]] = {}

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()

    def check(self, request: Request, key: str) -> None:
        limit = get_settings().rate_limit_per_minute
        window = int(time.time() // 60)
        with self._lock:
            start, count = self._windows.get(key, (window, 0))
            if start != window:
                start, count = window, 0
            count += 1
            self._windows[key] = (start, count)
        reset_in = 60 - int(time.time() % 60)
        request.state.rate_limit = (limit, max(0, limit - count), reset_in)
        if count > limit:
            raise APIError(429, "rate_limited", "Too many requests",
                           f"Rate limit of {limit} requests per minute exceeded.",
                           headers={"Retry-After": str(reset_in)})


limiter = FixedWindowLimiter()
