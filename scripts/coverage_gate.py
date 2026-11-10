#!/usr/bin/env python3
"""Coverage gate: parse a Cobertura ``coverage.xml`` and enforce per-package minimums.

Thresholds (line + branch coverage, combined the way coverage.py reports it):
  * overall                         >= 90%
  * agentguard/detectors            >= 95%
  * agentguard/scoring              >= 95%
  * agentguard/judges               >= 95%
  * agentguard/harness/canary.py    >= 95%

Prints a table and exits 1 if any threshold is missed (or the report is missing/empty).

Usage: uv run python scripts/coverage_gate.py [coverage.xml]
"""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET  # nosec B405 - parsing our own coverage report
from dataclasses import dataclass
from pathlib import Path

OVERALL_MIN = 90.0
SCOPES: list[tuple[str, float]] = [
    ("agentguard/detectors/", 95.0),
    ("agentguard/scoring/", 95.0),
    ("agentguard/judges/", 95.0),
    ("agentguard/harness/canary.py", 95.0),
]
_CONDITION = re.compile(r"\((\d+)/(\d+)\)")


@dataclass
class Tally:
    """Covered/total statements and branches."""

    statements: int = 0
    covered: int = 0
    branches: int = 0
    branches_covered: int = 0
    files: int = 0

    def add(self, other: Tally) -> None:
        """Accumulate ``other`` into this tally."""
        self.statements += other.statements
        self.covered += other.covered
        self.branches += other.branches
        self.branches_covered += other.branches_covered
        self.files += other.files

    @property
    def percent(self) -> float:
        """Combined line+branch coverage percentage (100 when there is nothing to cover)."""
        total = self.statements + self.branches
        return 100.0 * (self.covered + self.branches_covered) / total if total else 100.0


def _normalize(filename: str, sources: list[str]) -> str:
    """Path of a measured file relative to the package root, always starting with ``agentguard/``.

    coverage.py writes either ``src/agentguard/x.py`` (source = repo root) or ``x.py`` (source =
    the package directory) depending on how it was configured.
    """
    path = filename.replace("\\", "/")
    marker = "src/agentguard/"
    if marker in path:
        return path[path.rindex(marker) + len("src/") :]
    if path.startswith("agentguard/"):
        return path
    if any(s.replace("\\", "/").rstrip("/").endswith("/agentguard") for s in sources):
        return "agentguard/" + path
    return path


def parse(report: Path) -> dict[str, Tally]:
    """Per-file tallies from a Cobertura XML report."""
    root = ET.parse(report).getroot()  # nosec B314 - trusted local file
    sources = [s.text or "" for s in root.iter("source")]
    files: dict[str, Tally] = {}
    for cls in root.iter("class"):
        name = _normalize(cls.get("filename", ""), sources)
        tally = files.setdefault(name, Tally(files=1))
        for line in cls.iter("line"):
            tally.statements += 1
            if int(line.get("hits", "0")) > 0:
                tally.covered += 1
            if line.get("branch") == "true":
                match = _CONDITION.search(line.get("condition-coverage", ""))
                if match:
                    tally.branches_covered += int(match.group(1))
                    tally.branches += int(match.group(2))
    return files


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns the exit code."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report", nargs="?", default="coverage.xml", type=Path)
    args = parser.parse_args(argv)
    if not args.report.exists():
        print(f"coverage_gate: FAIL — {args.report} not found (run the tests with --cov-report=xml first)")
        return 1
    files = parse(args.report)
    if not files:
        print(f"coverage_gate: FAIL — {args.report} contains no measured files")
        return 1

    overall = Tally()
    for tally in files.values():
        overall.add(tally)
    rows: list[tuple[str, Tally, float]] = [("overall", overall, OVERALL_MIN)]
    for prefix, minimum in SCOPES:
        scope = Tally()
        for name, tally in files.items():
            if name == prefix or (prefix.endswith("/") and name.startswith(prefix)):
                scope.add(tally)
        rows.append((prefix.rstrip("/"), scope, minimum))

    failed = False
    header = (
        f"{'scope':<32} {'files':>5} {'stmts':>6} {'miss':>5} {'branch':>6} {'brmiss':>6} {'cover':>7} {'min':>5}"
        "  status"
    )
    print(header)
    print("-" * len(header))
    for name, tally, minimum in rows:
        ok = tally.files > 0 and tally.percent >= minimum
        failed |= not ok
        status = "ok" if ok else ("FAIL (no files measured)" if tally.files == 0 else "FAIL")
        print(
            f"{name:<32} {tally.files:>5} {tally.statements:>6} {tally.statements - tally.covered:>5} "
            f"{tally.branches:>6} {tally.branches - tally.branches_covered:>6} {tally.percent:>6.2f}% "
            f"{minimum:>4.0f}%  {status}"
        )
    worst = sorted(
        ((n, t) for n, t in files.items() if t.percent < 90.0),
        key=lambda item: item[1].percent,
    )[:10]
    if worst:
        print("\nlowest-covered files (< 90%):")
        for name, tally in worst:
            print(f"  {tally.percent:6.2f}%  {name}")
    print("\ncoverage_gate:", "FAIL" if failed else "PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
