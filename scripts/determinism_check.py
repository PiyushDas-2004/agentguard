#!/usr/bin/env python3
"""Determinism gate: two offline runs with the same seed must produce identical results.

Runs ``examples/demo.yaml`` (or ``--config``) twice on a category subset, with storage in fresh
temporary directories, and compares the JSON results after removing fields that legitimately
differ between runs (run id, timestamps, durations, latencies, git SHA, paths). Exits 1 and prints
the first differences when the runs diverge.

The normalizer (:func:`normalize`, :func:`normalize_text`) is reused by the snapshot and e2e tests.

Usage:
    uv run python scripts/determinism_check.py
    uv run python scripts/determinism_check.py --category PI_DIRECT --category DATA_EXFIL --trials 2
"""

from __future__ import annotations

import argparse
import asyncio
import difflib
import json
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

VOLATILE_KEYS = frozenset(
    {
        "run_id",
        "started_at",
        "ended_at",
        "timestamp",
        "duration_s",
        "latency_ms",
        "latency_p50_ms",
        "latency_p95_ms",
        "latency_p99_ms",
        "wall_time_s",
        "git_sha",
        "path",
        "db_path",
        "transcripts_dir",
        "out_dir",
    }
)
PLACEHOLDER = "<volatile>"
DEFAULT_CATEGORIES = ["PI_INDIRECT", "MEMORY_POISON", "OVER_REFUSAL"]
_RUN_ID = re.compile(r"\d{8}-\d{6}-[0-9a-f]{6}")
_DURATION = re.compile(r"(\*\*Duration:\*\* )[0-9.]+s")


def normalize_text(text: str) -> str:
    """Replace run ids and wall-clock durations inside free text (Markdown, messages)."""
    text = _RUN_ID.sub("<run_id>", text)
    return _DURATION.sub(r"\1<duration>s", text)


def normalize(value: Any, extra_keys: frozenset[str] = frozenset()) -> Any:
    """Recursively blank volatile keys (plus ``extra_keys``) and run ids so equal runs compare equal.

    ``config_hash`` is *not* volatile here: both runs use the same storage paths, so the hash must
    match. Callers whose configs differ only in temporary paths pass it in ``extra_keys``.
    """
    keys = VOLATILE_KEYS | extra_keys
    if isinstance(value, dict):
        return {k: (PLACEHOLDER if k in keys else normalize(v, extra_keys)) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(v, extra_keys) for v in value]
    if isinstance(value, str):
        return normalize_text(value)
    return value


def run_once(
    config_path: Path,
    categories: list[str] | None,
    trials: int | None,
    suite: str,
    seed: int | None,
    storage_dir: Path,
) -> dict[str, Any]:
    """Execute one offline run with isolated storage; return the result as JSON data."""
    from agentguard.config.loader import load_config
    from agentguard.core.runner import Runner, RunOptions
    from agentguard.core.types import AttackCategory

    config = load_config(config_path)
    # The same storage path for both runs keeps config_hash comparable; it is wiped before each run.
    shutil.rmtree(storage_dir, ignore_errors=True)
    storage_dir.mkdir(parents=True)
    try:
        storage = config.storage.model_copy(
            update={"db_path": str(storage_dir / "ag.db"), "transcripts_dir": str(storage_dir / "transcripts")}
        )
        run_cfg = config.run if seed is None else config.run.model_copy(update={"seed": seed})
        config = config.model_copy(update={"storage": storage, "run": run_cfg})
        options = RunOptions(
            suite=suite,
            categories=[AttackCategory(c) for c in categories] if categories else None,
            trials=trials,
            offline=True,
        )
        result = asyncio.run(Runner(config, options, base_dir=config_path.resolve().parent).run())
    finally:
        shutil.rmtree(storage_dir, ignore_errors=True)
    data: dict[str, Any] = json.loads(result.model_dump_json())
    return data


def diff(a: Any, b: Any, limit: int = 40) -> list[str]:
    """Unified diff of two normalized JSON documents (first ``limit`` lines)."""
    left = json.dumps(a, indent=1, sort_keys=True).splitlines()
    right = json.dumps(b, indent=1, sort_keys=True).splitlines()
    return list(difflib.unified_diff(left, right, "run-1", "run-2", lineterm="", n=2))[:limit]


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns the process exit code."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, default=ROOT / "examples" / "demo.yaml")
    parser.add_argument("--category", action="append", help=f"category subset (default {DEFAULT_CATEGORIES})")
    parser.add_argument("--trials", type=int, default=2)
    parser.add_argument("--suite", default="all", choices=["security", "quality", "all"])
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args(argv)
    categories = args.category or DEFAULT_CATEGORIES

    started = time.perf_counter()
    storage_dir = Path(tempfile.mkdtemp(prefix="agentguard-determinism-")) / "store"
    first = run_once(args.config, categories, args.trials, args.suite, args.seed, storage_dir)
    second = run_once(args.config, categories, args.trials, args.suite, args.seed, storage_dir)
    shutil.rmtree(storage_dir.parent, ignore_errors=True)
    elapsed = time.perf_counter() - started
    a, b = normalize(first), normalize(second)
    print(
        f"determinism: {args.config.name} categories={','.join(categories)} trials={args.trials} "
        f"suite={args.suite}: {first['total_trials']} trials/run, {len(first['cases'])} cases, "
        f"risk {first['risk_score']:.3f} vs {second['risk_score']:.3f} ({elapsed:.1f}s)"
    )
    if first["total_trials"] == 0:
        print("FAIL: the run produced no trials", file=sys.stderr)
        return 1
    if a != b:
        print("FAIL: results differ between two runs with the same seed:", file=sys.stderr)
        for line in diff(a, b):
            print("  " + line, file=sys.stderr)
        return 1
    print("OK: both runs are identical (excluding run id, timestamps, durations, latencies, git sha, paths)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
