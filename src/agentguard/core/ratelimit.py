"""Async token-bucket rate limiter."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable

__all__ = ["TokenBucket"]


class TokenBucket:
    """A token bucket that admits at most ``rate`` acquisitions per second on average.

    Tokens refill continuously; ``burst`` is the bucket capacity. ``acquire`` waits until a token is
    available. Waiters are served in FIFO order via an internal lock so the long-run rate holds even
    under heavy contention.

    Args:
        rate: tokens per second (``<= 0`` disables limiting).
        burst: bucket capacity (defaults to 1, which gives strict, evenly spaced pacing).
        clock: monotonic clock, injectable for tests.
    """

    def __init__(
        self,
        rate: float,
        burst: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.rate = float(rate)
        self.capacity = float(burst) if burst is not None else 1.0
        if self.capacity <= 0:
            raise ValueError("burst must be > 0")
        self._clock = clock
        self._tokens = self.capacity
        self._updated = clock()
        self._lock = asyncio.Lock()
        self.acquired = 0

    @property
    def enabled(self) -> bool:
        """Whether rate limiting is active."""
        return self.rate > 0

    def _refill(self) -> None:
        now = self._clock()
        elapsed = max(0.0, now - self._updated)
        self._updated = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)

    def wait_time(self) -> float:
        """Seconds until one token will be available (0 if available now)."""
        if not self.enabled:
            return 0.0
        self._refill()
        if self._tokens >= 1.0:
            return 0.0
        return (1.0 - self._tokens) / self.rate

    async def acquire(self) -> None:
        """Wait for and consume one token."""
        if not self.enabled:
            self.acquired += 1
            return
        async with self._lock:
            while True:
                delay = self.wait_time()
                if delay <= 0:
                    self._tokens -= 1.0
                    self.acquired += 1
                    return
                await asyncio.sleep(delay)
