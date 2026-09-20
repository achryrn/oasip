import asyncio
import time

import pytest


@pytest.mark.asyncio
async def test_rate_limiter_throttles():
    from oasip.limits import RateLimiter

    rl = RateLimiter(rate=50, burst=10, name="t")
    start = time.monotonic()
    for _ in range(10):
        async with rl:
            pass
    # burst should allow all 10 immediately
    assert time.monotonic() - start < 0.5


@pytest.mark.asyncio
async def test_rate_limiter_burst_then_throttle():
    from oasip.limits import RateLimiter

    rl = RateLimiter(rate=10, burst=2, name="t2")
    start = time.monotonic()
    for _ in range(8):
        async with rl:
            pass
    elapsed = time.monotonic() - start
    # 2 burst + 6 more at 10/s -> roughly 0.6s+
    assert elapsed >= 0.5
