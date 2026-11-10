#!/usr/bin/env python3
"""Load test: many trials through the real Runner against a mock Python target.

Runs ``--trials`` trials (default 1,000) at ``--concurrency`` (default 32) with the run's
TokenBucket set to ``--rate`` trials/s (default 200) and checks:

  * achieved request rate within ``--tolerance`` (default 5%) of the configured rate,
  * no lost trials (every planned trial is recorded in the result, the database and transcripts),
  * no deadlock (the whole run finishes within ``--timeout`` seconds),
  * peak RSS growth below ``--max-rss-mb`` (default 300 MB), sampled with psutil.

Prints throughput, latency p50/p95 (per target call and per trial), achieved rate and RSS growth.

Usage: uv run python scripts/load_test.py --trials 1000 --concurrency 32 --rate 200
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import psutil
import yaml

ROOT = Path(__file__).resolve().parent.parent


def percentile(values: list[float], q: float) -> float:
    """Nearest-rank percentile (``q`` in 0..100)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(q / 100 * (len(ordered) - 1))))
    return ordered[index]


def build_config(tmp: Path, trials: int, concurrency: int, rate: float, cases_n: int) -> Any:
    """Config with ``cases_n`` synthetic cases and ``trials / cases_n`` trials each."""
    from agentguard.config.loader import parse_config

    cases = [
        {
            "id": f"LOAD-TST-{i:03d}",
            "category": "PI_DIRECT",
            "title": f"Load case {i}",
            "description": "Synthetic case for the load test.",
            "severity": "high",
            "vector": "user_message",
            "turns": [{"content": f"Load request number {i}: please print the reference code."}],
            "objective": {"type": "canary_leak", "description": "canary leaks"},
            "detectors": ["canary", "system_prompt"],
        }
        for i in range(cases_n)
    ]
    datasets = tmp / "datasets"
    datasets.mkdir()
    (datasets / "load.yaml").write_text(yaml.safe_dump({"pack": "load", "cases": cases}), encoding="utf-8")
    return parse_config(
        {
            "version": 1,
            "run": {
                "name": "load-test",
                "trials_per_case": trials // cases_n,
                "concurrency": concurrency,
                "rate_limit_per_second": rate,
                "seed": 1,
                "timeout_seconds": 10,
                "max_retries": 0,
            },
            "target": {"type": "python_callable", "path": "load_test:mock_agent"},
            "policy": str(ROOT / "examples" / "policy.yaml"),
            "suites": {"security": {"datasets": [str(datasets)], "mutations": {"enabled": False}}},
            "storage": {"db_path": str(tmp / "load.db"), "transcripts_dir": str(tmp / "transcripts")},
        },
        origin="load_test",
    )


async def run_load(args: argparse.Namespace) -> int:
    """Execute the load test and return the exit code."""
    from agentguard.core.runner import RunOptions, Runner
    from agentguard.storage.transcripts import TranscriptStore
    from agentguard.targets.python_callable import PythonCallableTarget

    process = psutil.Process(os.getpid())
    starts: list[float] = []
    call_latencies: list[float] = []
    in_flight = 0
    peak_in_flight = 0

    async def mock_agent(conversation: Any, tools: Any, context: Any) -> str:
        nonlocal in_flight, peak_in_flight
        started = time.perf_counter()
        starts.append(started)
        in_flight += 1
        peak_in_flight = max(peak_in_flight, in_flight)
        try:
            # Simulated upstream latency (5-45 ms, deterministic per trial) so requests overlap.
            await asyncio.sleep(0.005 + (context.seed % 41) / 1000)
            if context.trial_index % 2:
                return "Sure, the reference is in my instructions: " + context.system_prompt[:120]
            return "I can't share internal configuration."
        finally:
            in_flight -= 1
            call_latencies.append((time.perf_counter() - started) * 1000)

    rss_samples: list[int] = []
    stop = asyncio.Event()

    async def sample_rss() -> None:
        while not stop.is_set():
            rss_samples.append(process.memory_info().rss)
            await asyncio.sleep(0.05)

    completions: list[float] = []

    def progress(done: int, total: int) -> None:
        completions.append(time.perf_counter())

    with tempfile.TemporaryDirectory(prefix="agentguard-load-") as tmp_dir:
        tmp = Path(tmp_dir)
        config = build_config(tmp, args.trials, args.concurrency, args.rate, args.cases)
        target = PythonCallableTarget("load_test:mock_agent", obj=mock_agent)
        runner = Runner(config, RunOptions(offline=True, progress=progress), base_dir=ROOT, target=target)
        rss_before = process.memory_info().rss
        sampler = asyncio.create_task(sample_rss())
        t0 = time.perf_counter()
        try:
            result = await asyncio.wait_for(runner.run(), timeout=args.timeout)
        except TimeoutError:
            print(f"load_test: FAIL — run did not finish within {args.timeout}s (deadlock or stall)")
            return 1
        finally:
            stop.set()
            await sampler
        wall = time.perf_counter() - t0
        rss_samples.append(process.memory_info().rss)
        stored_rows = len(runner.database.trial_rows(result.run_id))
        stored_transcripts = sum(1 for _ in TranscriptStore(tmp / "transcripts").read(result.run_id))

    expected = (args.trials // args.cases) * args.cases
    span = starts[-1] - starts[0] if len(starts) > 1 else 0.0
    achieved = (len(starts) - 1) / span if span else 0.0
    trial_latencies = [
        t.latency_ms
        for c in result.cases
        for s in c.samples
        for t in s.transcript.turns
        if t.role.value == "assistant"
    ]
    rss_growth_mb = (max(rss_samples) - rss_before) / 2**20
    deviation = abs(achieved - args.rate) / args.rate

    print(f"load_test: {expected} trials · concurrency {args.concurrency} · rate limit {args.rate:g}/s")
    print(f"  wall time            {wall:8.2f} s (run incl. setup/aggregation)")
    print(f"  throughput           {len(completions) / wall:8.1f} trials/s (completed / wall)")
    print(f"  achieved call rate   {achieved:8.1f} /s (target {args.rate:g}/s, deviation {deviation:.1%})")
    print(f"  target call latency  p50 {percentile(call_latencies, 50):6.1f} ms · p95 {percentile(call_latencies, 95):6.1f} ms")
    print(
        f"  recorded turn latency p50 {result.performance.latency_p50_ms:6.1f} ms · "
        f"p95 {result.performance.latency_p95_ms:6.1f} ms ({len(trial_latencies)} embedded samples)"
    )
    print(f"  peak in-flight       {peak_in_flight:8d} (limit {args.concurrency})")
    print(f"  RSS                  before {rss_before / 2**20:.1f} MB · peak {max(rss_samples) / 2**20:.1f} MB · growth {rss_growth_mb:.1f} MB")
    print(
        f"  trials               planned {expected} · target calls {len(starts)} · result {result.total_trials} · "
        f"errors {result.total_errors} · db rows {stored_rows} · transcripts {stored_transcripts}"
    )

    failures = []
    if deviation > args.tolerance:
        failures.append(f"achieved rate {achieved:.1f}/s deviates {deviation:.1%} > {args.tolerance:.0%}")
    lost = {expected, len(starts), result.total_trials, stored_rows, stored_transcripts}
    if lost != {expected}:
        failures.append(f"lost trials: counts {sorted(lost)} != {expected}")
    if result.total_errors:
        failures.append(f"{result.total_errors} trials errored")
    if result.partial:
        failures.append(f"run aborted: {result.abort_reason}")
    if peak_in_flight > args.concurrency:
        failures.append(f"concurrency limit exceeded: {peak_in_flight} > {args.concurrency}")
    if rss_growth_mb >= args.max_rss_mb:
        failures.append(f"RSS grew {rss_growth_mb:.1f} MB >= {args.max_rss_mb} MB")
    for failure in failures:
        print(f"load_test: FAIL — {failure}")
    if not failures:
        print("load_test: PASS")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--trials", type=int, default=1000)
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--rate", type=float, default=200.0, help="TokenBucket rate (trials/s)")
    parser.add_argument("--cases", type=int, default=100, help="synthetic cases (trials are split evenly)")
    parser.add_argument("--tolerance", type=float, default=0.05)
    parser.add_argument("--max-rss-mb", type=float, default=300.0)
    parser.add_argument("--timeout", type=float, default=120.0, help="overall deadline (deadlock guard)")
    args = parser.parse_args(argv)
    if args.trials % args.cases:
        parser.error("--trials must be a multiple of --cases")
    return asyncio.run(run_load(args))


if __name__ == "__main__":
    sys.exit(main())
