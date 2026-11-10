#!/usr/bin/env python3
"""Mutation-testing gate: mutmut over ``agentguard/scoring`` and ``agentguard/detectors``.

Configuration lives in ``[tool.mutmut]`` in ``pyproject.toml`` (mutate only scoring/ and
detectors/, run the unit tests). The gate runs ``mutmut run``, exports the statistics and
requires a mutation score of at least ``--min-score`` (default 75%):

    score = (killed + timeout + segfault) / (total - skipped - not_checked)

Timeouts and segfaults count as detected (the mutant changed observable behaviour). If mutmut
fails to run, the gate retries once from a clean ``mutants/`` directory and otherwise exits 2 with
mutmut's output — it never reports a pass it did not measure.

Usage: uv run python scripts/mutation_gate.py [--min-score 75] [--max-children N]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess  # nosec B404 - fixed argument lists, no shell
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MUTANTS = ROOT / "mutants"
STATS = MUTANTS / "mutmut-cicd-stats.json"


# mutmut 3.7 reads ``item._nodeid`` in its pytest hook; pytest 9 removed that private alias of
# ``nodeid``. This shim restores it before mutmut's CLI starts (forked mutant runs inherit it).
_SHIM = (
    "import _pytest.nodes as n\n"
    "if not hasattr(n.Node, '_nodeid'):\n"
    "    n.Node._nodeid = property(lambda self: self.nodeid)\n"
    "import sys\n"
    "from mutmut.__main__ import cli\n"
    "sys.argv[0] = 'mutmut'\n"
    "cli()\n"
)


def _mutmut(*args: str, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONWARNINGS": "ignore::UserWarning"}
    return subprocess.run(  # nosec B603
        [sys.executable, "-c", _SHIM, *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=env,
        timeout=timeout,
    )


def _tail(text: str, lines: int = 40) -> str:
    # mutmut draws spinners with carriage returns; keep only the final state of each line.
    cleaned = [line.rsplit("\r", 1)[-1] for line in text.splitlines()]
    return "\n".join(cleaned[-lines:])


def run_mutmut(max_children: int, timeout: float) -> bool:
    """Run mutmut, retrying once from a clean ``mutants/`` directory. Returns success."""
    for attempt in (1, 2):
        started = time.perf_counter()
        proc = _mutmut("run", "--max-children", str(max_children), timeout=timeout)
        elapsed = time.perf_counter() - started
        if proc.returncode == 0:
            print(f"mutation_gate: mutmut run finished in {elapsed:.0f}s (attempt {attempt})")
            return True
        print(f"mutation_gate: mutmut run failed (exit {proc.returncode}, attempt {attempt}):")
        print(_tail(proc.stdout + "\n" + proc.stderr))
        if attempt == 1:
            print("mutation_gate: retrying once from a clean mutants/ directory")
            shutil.rmtree(MUTANTS, ignore_errors=True)
    return False


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--min-score", type=float, default=75.0)
    parser.add_argument("--max-children", type=int, default=os.cpu_count() or 2)
    parser.add_argument("--timeout", type=float, default=3600.0, help="overall mutmut timeout (s)")
    parser.add_argument("--show-survivors", type=int, default=25)
    args = parser.parse_args(argv)

    if shutil.which("mutmut") is None and _mutmut("--version").returncode != 0:
        print("mutation_gate: FAIL — mutmut is not installed (uv sync --group dev)")
        return 2
    try:
        ok = run_mutmut(args.max_children, args.timeout)
    except subprocess.TimeoutExpired:
        print(f"mutation_gate: FAIL — mutmut did not finish within {args.timeout:.0f}s")
        return 2
    if not ok:
        print("mutation_gate: FAIL — mutmut could not run; no score was measured")
        return 2
    export = _mutmut("export-cicd-stats")
    if export.returncode != 0 or not STATS.exists():
        print("mutation_gate: FAIL — could not export mutmut statistics")
        print(_tail(export.stdout + export.stderr))
        return 2
    stats = json.loads(STATS.read_text(encoding="utf-8"))
    detected = stats.get("killed", 0) + stats.get("timeout", 0) + stats.get("segfault", 0)
    considered = stats.get("total", 0) - stats.get("skipped", 0) - stats.get("not_checked", 0)
    if considered <= 0:
        print(f"mutation_gate: FAIL — no mutants were checked: {stats}")
        return 2
    score = 100.0 * detected / considered

    print("mutation_gate: scope agentguard/scoring + agentguard/detectors (tests: tests/unit)")
    for key in ("total", "killed", "survived", "timeout", "suspicious", "no_tests", "skipped", "segfault"):
        print(f"  {key:<11} {stats.get(key, 0):>6}")
    print(f"  {'score':<11} {score:>5.1f}%  (detected {detected} / considered {considered}; min {args.min_score:g}%)")

    survivors = [
        line.split(":")[0].strip()
        for line in _mutmut("results").stdout.splitlines()
        if line.strip().endswith(": survived")
    ]
    if survivors:
        by_module: dict[str, int] = {}
        for name in survivors:
            module = name.split(".x_")[0] if ".x_" in name else name.rsplit(".", 1)[0]
            by_module[module] = by_module.get(module, 0) + 1
        print("  surviving mutants by module:")
        for module, count in sorted(by_module.items(), key=lambda item: -item[1]):
            print(f"    {count:>4}  {module}")
        for name in survivors[: args.show_survivors]:
            print(f"    survived: {name}")
        print("  inspect one with: uv run mutmut show <name>")

    if score < args.min_score:
        print(f"mutation_gate: FAIL — score {score:.1f}% < {args.min_score:g}%")
        return 1
    print(f"mutation_gate: PASS — score {score:.1f}% >= {args.min_score:g}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
