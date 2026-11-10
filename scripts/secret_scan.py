#!/usr/bin/env python3
"""Secret scan: detect-secrets over the working tree, compared with ``.secrets.baseline``.

Every finding must already be in the committed baseline (matched on file, secret hash and type,
ignoring line numbers). The baseline may only contain findings in paths listed in
:data:`JUSTIFIED` below — synthetic canaries, attack-prompt bait and test fixtures — each with
the reason it is not a real secret. Anything else fails the gate.

Usage:
    uv run python scripts/secret_scan.py                    # check (CI)
    uv run python scripts/secret_scan.py --update-baseline  # after reviewing new findings

``--update-baseline`` rewrites the baseline from the current tree but refuses (exit 1) when a
finding lies outside the justified paths, so a real secret can never be baselined by accident.
"""

from __future__ import annotations

import argparse
import json
import subprocess  # nosec B404 - fixed argument list, no shell
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / ".secrets.baseline"

EXCLUDE_FILES = [
    r"(^|/)(\.venv|\.git|mutants|\.agentguard|reports|htmlcov|node_modules|__pycache__|\.mypy_cache|"
    r"\.ruff_cache|\.hypothesis|\.pytest_cache)/",
    r"\.(pyc|db|sqlite3?|gz|png|jpe?g|ico|woff2?)$",
    r"^uv\.lock$",  # package hashes
    r"^coverage\.xml$",
    r"^\.secrets\.baseline$",
    r"^src/agentguard/dashboard/static/htmx\.min\.js$",  # vendored, minified third-party library
]

# path prefix -> why findings there are not real secrets (printed with every run)
JUSTIFIED: dict[str, str] = {
    "tests/": "test fixtures: synthetic canaries (AG-CANARY-*), fake API keys, PII/IBAN test vectors",
    "datasets/": "attack prompts that bait the agent with fake credentials; no real secrets",
    "examples/targets/": "demo agents: synthetic canary tokens declared as known_secrets and "
    "translation word lists ('secreto'/'contraseña')",
    "src/agentguard/harness/environment.py": "seeded virtual environment: fake /etc/passwd and generated "
    "account ids planted as bait inside the sandbox",
    "src/agentguard/llm/textnorm.py": "mock translation dictionary entries ('secret' -> 'secreto')",
}


def scan() -> dict[str, list[dict[str, Any]]]:
    """Run detect-secrets on every file in the tree (tracked or not) and return its results."""
    cmd = [sys.executable, "-m", "detect_secrets", "scan", "--all-files"]
    for pattern in EXCLUDE_FILES:
        cmd += ["--exclude-files", pattern]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)  # nosec B603
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "detect-secrets failed")
    data: dict[str, Any] = json.loads(proc.stdout)
    results: dict[str, list[dict[str, Any]]] = data["results"]
    return results


def _keys(results: dict[str, list[dict[str, Any]]]) -> set[tuple[str, str, str]]:
    return {(f, i["hashed_secret"], i["type"]) for f, items in results.items() for i in items}


def _justification(filename: str) -> str | None:
    for prefix, reason in JUSTIFIED.items():
        if filename == prefix or (prefix.endswith("/") and filename.startswith(prefix)):
            return reason
    return None


def update_baseline(results: dict[str, list[dict[str, Any]]]) -> int:
    """Write the baseline from ``results`` if every finding is in a justified path."""
    unjustified = sorted(f for f in results if _justification(f) is None)
    if unjustified:
        print("secret_scan: refusing to baseline findings outside justified paths:")
        for name in unjustified:
            for item in results[name]:
                print(f"  {name}:{item['line_number']} {item['type']}")
        return 1
    cmd = [sys.executable, "-m", "detect_secrets", "scan", "--all-files"]
    for pattern in EXCLUDE_FILES:
        cmd += ["--exclude-files", pattern]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=True)  # nosec B603
    baseline = json.loads(proc.stdout)
    for items in baseline["results"].values():
        for item in items:
            item["is_secret"] = False  # reviewed: synthetic (see JUSTIFIED in scripts/secret_scan.py)
    baseline.pop("generated_at", None)
    BASELINE.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    total = sum(len(v) for v in baseline["results"].values())
    print(f"secret_scan: wrote {BASELINE.name} with {total} reviewed synthetic findings in {len(results)} files")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--update-baseline", action="store_true")
    args = parser.parse_args(argv)
    try:
        results = scan()
    except (RuntimeError, json.JSONDecodeError) as exc:
        print(f"secret_scan: FAIL — detect-secrets could not run: {exc}")
        return 1
    if args.update_baseline:
        return update_baseline(results)
    if not BASELINE.exists():
        print(f"secret_scan: FAIL — {BASELINE.name} is missing (run with --update-baseline after review)")
        return 1
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    allowed = _keys(baseline.get("results", {}))
    bad_baseline = sorted(f for f in baseline.get("results", {}) if _justification(f) is None)

    current = _keys(results)
    new = sorted(current - allowed)
    n_files = len({f for f, _, _ in current})
    print(f"secret_scan: detect-secrets found {len(current)} candidate(s) in {n_files} file(s)")
    print(f"secret_scan: baseline holds {len(allowed)} reviewed synthetic finding(s); justified paths:")
    for prefix, reason in JUSTIFIED.items():
        print(f"  {prefix:<40} {reason}")
    failed = False
    if bad_baseline:
        failed = True
        print("secret_scan: FAIL — baseline contains findings outside the justified paths:")
        for name in bad_baseline:
            print(f"  {name}")
    if new:
        failed = True
        print(f"secret_scan: FAIL — {len(new)} finding(s) not in the baseline:")
        lines = {(f, i["hashed_secret"], i["type"]): i["line_number"] for f, items in results.items() for i in items}
        for filename, hashed, kind in new:
            where = "justified path — review, then --update-baseline" if _justification(filename) else "UNJUSTIFIED"
            print(f"  {filename}:{lines[(filename, hashed, kind)]} {kind} ({where})")
    stale = len(allowed - current)
    if stale:
        print(f"secret_scan: note — {stale} baseline entr(y/ies) no longer present (refresh with --update-baseline)")
    if failed:
        return 1
    print("secret_scan: PASS — no unreviewed secrets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
