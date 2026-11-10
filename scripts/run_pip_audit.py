#!/usr/bin/env python3
"""Dependency vulnerability audit of the *locked* environment.

Exports ``uv.lock`` (all extras + dev group, no hashes, without the project itself) to a
requirements file and runs ``pip-audit -r <file> --disable-pip`` against the PyPI advisory
database (OSV via PyPI JSON API). Known, assessed advisories can be ignored below — each entry
MUST carry a reason and is printed in the output so the decision stays visible.

Exit codes: 0 no unignored vulnerabilities · 1 vulnerabilities found · 2 audit could not run.

Usage: uv run python scripts/run_pip_audit.py [--json]
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess  # nosec B404 - fixed argument lists, no shell
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# advisory id -> reason it is accepted. Keep this list short and justified; review on every bump.
IGNORED: dict[str, str] = {
    # Reviewed 2026-11-10. Both come only from the optional `ragas` extra (agentguard[ragas]/[all]);
    # neither is in the core install or the Docker image, and no fixed release exists yet.
    "PYSEC-2026-3046": (
        "ragas<=0.4.3 SSRF in multi_modal_faithfulness util (CVE-2026-6587). AgentGuard's ragas "
        "adapter only uses faithfulness/answer_relevancy/context_precision/context_recall, never the "
        "multi-modal collection, and retrieved_contexts come from our own fixture corpus."
    ),
    "PYSEC-2026-2447": (
        "diskcache<=5.6.3 pickle deserialization (CVE-2025-69872), pulled in by ragas. Exploitation "
        "requires write access to the local cache directory, i.e. an attacker who already runs as "
        "the user; AgentGuard never points diskcache at shared or untrusted directories."
    ),
}


def export_requirements(target: Path) -> None:
    """Write the locked dependency set (all extras, dev group) as a requirements file."""
    uv = shutil.which("uv")
    if uv is None:
        raise RuntimeError("uv is not on PATH")
    subprocess.run(  # nosec B603
        [
            uv,
            "export",
            "--frozen",
            "--format",
            "requirements-txt",
            "--no-hashes",
            "--all-extras",
            "--all-groups",
            "--no-emit-project",
            "-o",
            str(target),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="print the raw pip-audit JSON")
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="agentguard-audit-") as tmp:
        requirements = Path(tmp) / "requirements.txt"
        try:
            export_requirements(requirements)
        except (subprocess.CalledProcessError, RuntimeError) as exc:
            detail = getattr(exc, "stderr", "") or str(exc)
            print(f"run_pip_audit: cannot export uv.lock: {detail}", file=sys.stderr)
            return 2
        n_reqs = sum(1 for line in requirements.read_text().splitlines() if line and not line.startswith(("#", " ")))
        cmd = [
            sys.executable,
            "-m",
            "pip_audit",
            "-r",
            str(requirements),
            "--disable-pip",
            "--no-deps",  # the export is the complete, pinned transitive closure
            "--progress-spinner",
            "off",
            "--format",
            "json",
        ]
        for vuln_id in IGNORED:
            cmd += ["--ignore-vuln", vuln_id]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)  # nosec B603
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print("run_pip_audit: pip-audit did not produce a report:", file=sys.stderr)
        print(proc.stderr.strip() or proc.stdout.strip(), file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))

    deps = list({(d["name"], d.get("version")): d for d in report.get("dependencies", [])}.values())
    vulnerable = [d for d in deps if d.get("vulns")]
    skipped = [d for d in deps if d.get("skip_reason")]
    print(f"run_pip_audit: audited {len(deps)} locked packages ({n_reqs} requirements, all extras + dev group)")
    for name, reason in IGNORED.items():
        print(f"  ignored {name}: {reason}")
    for dep in skipped:
        print(f"  skipped {dep['name']}: {dep['skip_reason']}")
    if not vulnerable:
        print("run_pip_audit: PASS — no known vulnerabilities outside the reviewed ignore list")
        return 0
    print("run_pip_audit: FAIL — known vulnerabilities:")
    seen: set[tuple[str, str, str]] = set()
    for dep in vulnerable:
        for vuln in dep["vulns"]:
            key = (dep["name"], dep["version"], vuln["id"])
            if key in seen:
                continue
            seen.add(key)
            fixes = ", ".join(vuln.get("fix_versions") or []) or "no fix released"
            aliases = ", ".join(vuln.get("aliases") or [])
            print(f"  {dep['name']} {dep['version']}: {vuln['id']} ({aliases}) fix: {fixes}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
