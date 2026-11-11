"""Bounded-concurrency, rate-limited trial scheduler with clean cancellation."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Generic, TypeVar

from agentguard.core.errors import BudgetExceededError
from agentguard.core.ratelimit import TokenBucket

__all__ = ["SchedulerOutcome", "TrialScheduler"]

T = TypeVar("T")
R = TypeVar("R")


@dataclass
class SchedulerOutcome(Generic[R]):
    """What the scheduler finished before stopping.

    Attributes:
        results: results in completion order.
        aborted: reason the run stopped early (``budget`` or ``interrupted``), else ``None``.
        error: the exception that aborted the run, if any.
        peak_in_flight: maximum concurrently running workers observed.
    """

    results: list[R] = field(default_factory=list)
    aborted: str | None = None
    error: BaseException | None = None
    peak_in_flight: int = 0


class TrialScheduler:
    """Runs workers with at most ``concurrency`` in flight and an optional rate limit.

    A :class:`BudgetExceededError` from any worker cancels the remaining work (``aborted =
    "budget"``); ``KeyboardInterrupt``/cancellation stops it with ``aborted = "interrupted"``.
    Results finished before the stop are preserved.
    """

    def __init__(self, concurrency: int, limiter: TokenBucket | None = None) -> None:
        if concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        self.concurrency = concurrency
        self.limiter = limiter
        self._in_flight = 0

    async def run(
        self,
        items: Sequence[T],
        worker: Callable[[T], Awaitable[R]],
        on_result: Callable[[R], None] | None = None,
    ) -> SchedulerOutcome[R]:
        """Process ``items`` and return the outcome (never raises for budget/interrupt)."""
        outcome: SchedulerOutcome[R] = SchedulerOutcome()
        semaphore = asyncio.Semaphore(self.concurrency)
        queue = list(items)
        stop = asyncio.Event()

        async def guarded(item: T) -> R:
            async with semaphore:
                if stop.is_set():
                    raise asyncio.CancelledError
                if self.limiter is not None:
                    await self.limiter.acquire()
                self._in_flight += 1
                outcome.peak_in_flight = max(outcome.peak_in_flight, self._in_flight)
                try:
                    result = await worker(item)
                except KeyboardInterrupt as exc:
                    # Raised inside a task, KeyboardInterrupt would escape the event loop and skip
                    # cleanup on Python 3.11; turn it into a clean, recorded abort instead.
                    outcome.aborted, outcome.error = "interrupted", exc
                    stop.set()
                    raise asyncio.CancelledError from exc
                finally:
                    self._in_flight -= 1
                outcome.results.append(result)
                if on_result is not None:
                    on_result(result)
                return result

        tasks = [asyncio.create_task(guarded(item)) for item in queue]
        try:
            for future in asyncio.as_completed(tasks):
                try:
                    await future
                except asyncio.CancelledError:
                    if outcome.aborted == "interrupted":
                        break
                    if stop.is_set():
                        continue
                    raise
                except BudgetExceededError as exc:
                    outcome.aborted, outcome.error = "budget", exc
                    stop.set()
                    break
        except (KeyboardInterrupt, asyncio.CancelledError) as exc:
            outcome.aborted, outcome.error = "interrupted", exc
            stop.set()
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        return outcome
