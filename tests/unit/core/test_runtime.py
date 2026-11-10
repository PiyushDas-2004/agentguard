"""Seeds, TokenBucket, TrialScheduler and Tracer."""

from __future__ import annotations

import asyncio

import pytest

from agentguard.core.errors import BudgetExceededError
from agentguard.core.ratelimit import TokenBucket
from agentguard.core.scheduler import TrialScheduler
from agentguard.core.seeds import derive_rng, derive_seed, stable_hash
from agentguard.core.tracing import Span, Tracer


class TestSeeds:
    def test_stable_hash_known(self) -> None:
        import hashlib

        assert stable_hash("a", 1) == hashlib.sha256(b"a\x1f1").hexdigest()

    def test_derive_seed_deterministic(self) -> None:
        assert derive_seed(1337, "C-001", 0) == derive_seed(1337, "C-001", 0)
        assert derive_seed(1337, "C-001", 0) != derive_seed(1337, "C-001", 1)
        assert derive_seed(1337, "C-001") != derive_seed(1338, "C-001")
        assert 0 <= derive_seed(1, "x") < 2**63

    def test_derive_rng(self) -> None:
        a = [derive_rng(7, "x").random() for _ in range(3)]
        b = [derive_rng(7, "x").random() for _ in range(3)]
        assert a == b
        r = derive_rng(7, "x")
        assert [r.random() for _ in range(2)] != [r.random() for _ in range(2)]


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class TestTokenBucket:
    def test_disabled(self) -> None:
        bucket = TokenBucket(0)
        assert not bucket.enabled
        assert bucket.wait_time() == 0.0
        for _ in range(100):
            asyncio.run(bucket.acquire())
        assert bucket.acquired == 100

    def test_bad_burst(self) -> None:
        with pytest.raises(ValueError, match="burst"):
            TokenBucket(1, burst=0)

    def test_rate_with_fake_clock(self) -> None:
        clock = FakeClock()
        bucket = TokenBucket(2.0, clock=clock)
        assert bucket.wait_time() == 0.0
        bucket._tokens -= 1  # consume
        assert bucket.wait_time() == pytest.approx(0.5)
        clock.now = 0.25
        assert bucket.wait_time() == pytest.approx(0.25)
        clock.now = 0.5
        assert bucket.wait_time() == 0.0

    def test_burst_capacity(self) -> None:
        clock = FakeClock()
        bucket = TokenBucket(1.0, burst=3, clock=clock)

        async def take(n: int) -> None:
            for _ in range(n):
                await bucket.acquire()

        asyncio.run(take(3))
        assert bucket.acquired == 3
        assert bucket.wait_time() == pytest.approx(1.0)
        clock.now = 100.0  # refill is capped at capacity
        assert bucket._tokens <= 3
        bucket.wait_time()
        assert bucket._tokens == 3

    def test_clock_going_backwards_is_ignored(self) -> None:
        clock = FakeClock()
        clock.now = 10
        bucket = TokenBucket(1.0, clock=clock)
        bucket._tokens = 0.0
        clock.now = 5
        assert bucket.wait_time() == pytest.approx(1.0)

    def test_acquire_waits_until_refilled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        clock = FakeClock()
        bucket = TokenBucket(4.0, clock=clock)
        sleeps: list[float] = []

        async def fake_sleep(delay: float) -> None:
            sleeps.append(delay)
            clock.now += delay

        monkeypatch.setattr("agentguard.core.ratelimit.asyncio.sleep", fake_sleep)

        async def go() -> None:
            for _ in range(5):
                await bucket.acquire()

        asyncio.run(go())
        assert bucket.acquired == 5
        assert sleeps == pytest.approx([0.25] * 4)
        assert clock.now == pytest.approx(1.0)  # 5 tokens at 4/s with burst 1


class TestTrialScheduler:
    def test_bad_concurrency(self) -> None:
        with pytest.raises(ValueError, match="concurrency"):
            TrialScheduler(0)

    def test_peak_in_flight_and_results(self) -> None:
        scheduler = TrialScheduler(3)
        seen: list[int] = []
        live = 0
        peak = 0

        async def worker(i: int) -> int:
            nonlocal live, peak
            live += 1
            peak = max(peak, live)
            await asyncio.sleep(0.001 * (i % 3))
            live -= 1
            return i * 2

        outcome = asyncio.run(scheduler.run(list(range(20)), worker, on_result=seen.append))
        assert sorted(outcome.results) == [i * 2 for i in range(20)]
        assert sorted(seen) == sorted(outcome.results)
        assert outcome.aborted is None
        assert outcome.error is None
        assert 1 <= outcome.peak_in_flight <= 3
        assert peak <= 3
        assert outcome.peak_in_flight == 3

    def test_with_limiter(self) -> None:
        bucket = TokenBucket(0)
        outcome = asyncio.run(TrialScheduler(2, bucket).run([1, 2, 3], _echo))
        assert sorted(outcome.results) == [1, 2, 3]
        assert bucket.acquired == 3

    def test_empty(self) -> None:
        outcome = asyncio.run(TrialScheduler(2).run([], _echo))
        assert outcome.results == []
        assert outcome.peak_in_flight == 0

    def test_budget_abort_keeps_finished(self) -> None:
        async def worker(i: int) -> int:
            if i == 5:
                await asyncio.sleep(0.01)
                raise BudgetExceededError("cap")
            if i > 5:
                await asyncio.sleep(1)
            return i

        outcome = asyncio.run(TrialScheduler(1).run(list(range(10)), worker))
        assert outcome.aborted == "budget"
        assert isinstance(outcome.error, BudgetExceededError)
        assert sorted(outcome.results) == [0, 1, 2, 3, 4]

    def test_budget_abort_concurrent(self) -> None:
        async def worker(i: int) -> int:
            if i == 0:
                raise BudgetExceededError("cap")
            await asyncio.sleep(5)
            return i

        outcome = asyncio.run(asyncio.wait_for(TrialScheduler(4).run(list(range(8)), worker), 3))
        assert outcome.aborted == "budget"
        assert outcome.results == []

    def test_cancellation_is_interrupted(self) -> None:
        done: list[int] = []

        async def worker(i: int) -> int:
            if i < 2:
                return i
            await asyncio.sleep(10)
            return i

        async def main() -> object:
            task = asyncio.create_task(TrialScheduler(2).run(list(range(6)), worker, on_result=done.append))
            await asyncio.sleep(0.05)
            task.cancel()
            return await task

        outcome = asyncio.run(main())
        assert outcome.aborted == "interrupted"  # type: ignore[attr-defined]
        assert sorted(outcome.results) == [0, 1]  # type: ignore[attr-defined]
        assert sorted(done) == [0, 1]

    def test_worker_cancelled_error_propagates_as_interrupt(self) -> None:
        async def worker(i: int) -> int:
            raise asyncio.CancelledError

        outcome = asyncio.run(TrialScheduler(1).run([1], worker))
        assert outcome.aborted == "interrupted"

    def test_other_exceptions_propagate(self) -> None:
        async def worker(i: int) -> int:
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            asyncio.run(TrialScheduler(1).run([1], worker))


async def _echo(i: int) -> int:
    return i


class TestTracer:
    def test_nesting(self) -> None:
        tracer = Tracer()
        with tracer.span("run", "r", seed=1) as run, tracer.span("case", "c") as case:
            with tracer.span("trial", "t") as trial:
                assert trial.parent_id == case.span_id
            assert case.parent_id == run.span_id
        assert run.parent_id is None
        assert [s.kind for s in tracer.spans] == ["trial", "case", "run"]
        assert run.attributes == {"seed": 1}
        assert all(s.end_ns is not None and s.duration_ms >= 0 for s in tracer.spans)
        assert tracer.by_kind("case") == [case]

    def test_error_status(self) -> None:
        tracer = Tracer()
        with pytest.raises(ValueError), tracer.span("turn", "x"):
            raise ValueError("bad")
        assert tracer.spans[0].status == "error"
        # context restored after error
        with tracer.span("run", "after") as s:
            assert s.parent_id is None

    def test_open_span_duration_zero(self) -> None:
        assert Span(kind="run", name="x").duration_ms == 0.0

    def test_max_spans(self) -> None:
        tracer = Tracer(max_spans=2)
        for i in range(5):
            with tracer.span("tool_call", str(i)):
                pass
        assert len(tracer.spans) == 2
        assert tracer.dropped == 3

    def test_otel_mirror(self) -> None:
        pytest.importorskip("opentelemetry")
        tracer = Tracer(otel=True)
        assert tracer._otel_tracer is not None
        with tracer.span("judge_call", "j", model="m", n=1, obj=object()):
            pass
        assert len(tracer.spans) == 1

    def test_otel_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import builtins

        real_import = builtins.__import__

        def fake_import(name: str, *args: object, **kwargs: object) -> object:
            if name.startswith("opentelemetry"):
                raise ImportError(name)
            return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(builtins, "__import__", fake_import)
        assert Tracer(otel=True)._otel_tracer is None
