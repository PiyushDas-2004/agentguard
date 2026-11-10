"""Dataset-authoring helper: run cases against demo agents and show per-case outcomes.

Usage:
    uv run python scripts/probe_cases.py datasets/attacks/pi_direct.yaml [--trials 3] [--agents vulnerable,hardened]

For each case prints the violation counts per agent, the detectors that fired, and flags:
  MISS  - the vulnerable agent was not caught (case may not be understood / reachable)
  FP    - the hardened agent was flagged (a defense bypass or a detector false positive)
"""

from __future__ import annotations

import argparse
import asyncio
import tempfile
from pathlib import Path

from agentguard.config.loader import parse_config
from agentguard.core.runner import Runner, RunOptions

AGENTS = {
    "vulnerable": "examples/targets/vulnerable_agent.py:agent",
    "partial": "examples/targets/partially_hardened_agent.py:agent",
    "hardened": "examples/targets/hardened_agent.py:agent",
    "rag": "examples/targets/rag_agent.py:agent",
    "rag_hardened": "examples/targets/rag_agent.py:hardened",
}


async def probe(paths: list[str], trials: int, agents: list[str], mutations: bool) -> None:
    tmp = Path(tempfile.mkdtemp(prefix="agentguard-probe-"))
    table: dict[str, dict[str, str]] = {}
    for agent in agents:
        cfg = parse_config(
            {
                "run": {"name": f"probe-{agent}", "trials_per_case": trials, "concurrency": 8, "seed": 7},
                "target": {"type": "python_callable", "path": AGENTS[agent]},
                "policy": "examples/policy.yaml",
                "suites": {"security": {"datasets": paths, "mutations": {"enabled": mutations, "per_case": 2}}},
                "storage": {"db_path": str(tmp / "probe.db"), "transcripts_dir": str(tmp / "tr")},
            }
        )
        result = await Runner(cfg, RunOptions(offline=True, strict=True)).run()
        for case in result.cases:
            fired = ",".join(f"{k}:{v}" for k, v in case.detectors_triggered.items())
            table.setdefault(case.case_id, {})[agent] = (
                f"{case.n_violations}/{case.n_trials} {case.status.value[:4]} [{fired}]"
            )
    for case_id in sorted(table):
        row = table[case_id]
        flags = []
        vuln = row.get("vulnerable", "")
        hard = row.get("hardened", "")
        if vuln.startswith("0/") and not case_id.startswith("BEN"):
            flags.append("MISS")
        if hard and not hard.startswith("0/") and not case_id.startswith("BEN"):
            flags.append("FP")
        if case_id.startswith("BEN") and vuln and not vuln.startswith("0/"):
            flags.append("FP-BENIGN")
        print(case_id, " | ".join(f"{a}={row.get(a, '-')}" for a in agents), " ".join(flags))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--agents", default="vulnerable,hardened")
    parser.add_argument("--mutations", action="store_true")
    args = parser.parse_args()
    asyncio.run(probe(args.paths, args.trials, args.agents.split(","), args.mutations))


if __name__ == "__main__":
    main()
