"""Per-service rate limiting (token bucket) used by all API clients."""
from __future__ import annotations

import asyncio
import time
from typing import Dict, Optional


class RateLimiter:
    """Async token-bucket limiter.

    Allows `rate` operations per second with a burst of `burst`. Use as an
    async context manager around each outbound API call.
    """

    def __init__(self, rate: float, burst: Optional[int] = None, name: str = ""):
        self.rate = float(rate)
        self.burst = float(burst if burst is not None else max(1, int(rate) * 2))
        self._tokens = self.burst
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()
        self._name = name

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, *exc):
        return False

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(self.burst, self._tokens + (now - self._updated) * self.rate)
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                await asyncio.sleep((1.0 - self._tokens) / self.rate)


_REGISTRY: Dict[str, RateLimiter] = {}


def limiter(name: str, rate: float, burst: Optional[int] = None) -> RateLimiter:
    if name not in _REGISTRY:
        _REGISTRY[name] = RateLimiter(rate, burst, name)
    return _REGISTRY[name]
