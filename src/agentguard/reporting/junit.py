"""JUnit XML report: one testcase per case, grouped by category; failures carry evidence."""

from __future__ import annotations

import xml.etree.ElementTree as ET  # only *writes* XML (never parses)  # nosec B405

from agentguard.core.types import CaseStatus, RunResult

__all__ = ["render_junit"]


def _sanitize(text: str) -> str:
    return "".join(ch for ch in text if ch in "\t\n\r" or ord(ch) >= 0x20)


def render_junit(result: RunResult) -> str:
    """Render the run as JUnit XML (inconclusive cases are reported as skipped)."""
    root = ET.Element(
        "testsuites",
        name=f"agentguard:{result.name}",
        tests=str(len(result.cases)),
        failures=str(sum(1 for c in result.cases if c.status == CaseStatus.failed)),
        time=f"{result.duration_s:.3f}",
    )
    by_category: dict[str, list[int]] = {}
    for i, case in enumerate(result.cases):
        by_category.setdefault(case.category.value, []).append(i)
    for category, indexes in by_category.items():
        cases = [result.cases[i] for i in indexes]
        suite = ET.SubElement(
            root,
            "testsuite",
            name=category,
            tests=str(len(cases)),
            failures=str(sum(1 for c in cases if c.status == CaseStatus.failed)),
            skipped=str(sum(1 for c in cases if c.status == CaseStatus.inconclusive)),
            errors="0",
            time="0",
        )
        for case in cases:
            testcase = ET.SubElement(
                suite,
                "testcase",
                classname=f"agentguard.{category}",
                name=f"{case.case_id} {_sanitize(case.title)}",
                time="0",
            )
            summary = (
                f"violations {case.n_violations}/{case.n_trials} (rate {case.violation_rate:.2f}, "
                f"CI {case.ci_low:.2f}-{case.ci_high:.2f}), errors {case.n_errors}, severity {case.severity.value}"
            )
            if case.status == CaseStatus.failed:
                failure = ET.SubElement(testcase, "failure", message=_sanitize(summary), type=case.severity.value)
                lines = [summary]
                for sample in case.samples:
                    for verdict in sample.verdicts:
                        if verdict.violated:
                            for ev in verdict.evidence[:3]:
                                lines.append(f"[{verdict.detector_id}] {ev.reason}: {ev.text[:200]}")
                failure.text = _sanitize("\n".join(lines))
            elif case.status == CaseStatus.inconclusive:
                ET.SubElement(testcase, "skipped", message=_sanitize("inconclusive: " + summary))
            ET.SubElement(testcase, "system-out").text = _sanitize(summary)
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")
