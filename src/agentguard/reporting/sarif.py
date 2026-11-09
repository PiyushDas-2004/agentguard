"""SARIF 2.1.0 report: one rule per attack category, one result per failing case."""

from __future__ import annotations

import json
from typing import Any

from agentguard.attacks.registry import CATEGORY_INFO
from agentguard.core.types import AttackCategory, CaseStatus, RunResult, Severity
from agentguard.reporting.remediation import REMEDIATION
from agentguard.scoring.owasp import CATEGORY_OWASP, OWASP_LLM_2025, owasp_url

__all__ = ["SARIF_SCHEMA_URI", "build_sarif", "level_for", "render_sarif"]

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVELS = {
    Severity.critical: "error",
    Severity.high: "error",
    Severity.medium: "warning",
    Severity.low: "note",
    Severity.info: "note",
}
_SECURITY_SEVERITY = {
    Severity.critical: "9.5",
    Severity.high: "8.0",
    Severity.medium: "5.5",
    Severity.low: "2.0",
    Severity.info: "0.0",
}


def level_for(severity: Severity) -> str:
    """Map AgentGuard severity to a SARIF level (critical/high=error, medium=warning, else note)."""
    return _LEVELS[severity]


def _rule(category: AttackCategory) -> dict[str, Any]:
    info = CATEGORY_INFO[category]
    owasp = CATEGORY_OWASP[category]
    primary = owasp[0] if owasp else None
    help_lines = [info.summary, "", "Remediation:"] + [f"- {r}" for r in REMEDIATION[category]]
    if primary:
        help_lines += ["", f"OWASP: {primary} {OWASP_LLM_2025[primary]} — {owasp_url(primary)}"]
    rule: dict[str, Any] = {
        "id": f"AG-{category.value}",
        "name": "".join(part.capitalize() for part in category.value.split("_")),
        "shortDescription": {"text": info.title},
        "fullDescription": {"text": info.summary},
        "help": {"text": "\n".join(help_lines), "markdown": "\n".join(help_lines)},
        "properties": {"tags": ["security", "llm", *owasp]},
    }
    if primary:
        rule["helpUri"] = owasp_url(primary)
    return rule


def build_sarif(result: RunResult, *, config_path: str = "agentguard.yaml") -> dict[str, Any]:
    """Build the SARIF log as a dict (validated against the official schema in tests)."""
    categories = [c for c in AttackCategory if c != AttackCategory.OVER_REFUSAL]
    rules = [_rule(c) for c in categories]
    index = {c: i for i, c in enumerate(categories)}
    results: list[dict[str, Any]] = []
    for case in result.cases:
        if case.status != CaseStatus.failed or case.category == AttackCategory.OVER_REFUSAL:
            continue
        evidence = next(
            (v.evidence[0].reason for s in case.samples for v in s.verdicts if v.violated and v.evidence), ""
        )
        message = (
            f"{case.case_id} {case.title}: violated in {case.n_violations}/{case.n_trials} trials "
            f"(rate {case.violation_rate:.0%}, 95% CI {case.ci_low:.2f}-{case.ci_high:.2f})."
        )
        if evidence:
            message += f" Evidence: {evidence}"
        results.append(
            {
                "ruleId": f"AG-{case.category.value}",
                "ruleIndex": index[case.category],
                "level": level_for(case.severity),
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {"artifactLocation": {"uri": config_path}, "region": {"startLine": 1}},
                        "logicalLocations": [{"name": case.case_id, "kind": "test"}],
                    }
                ],
                "partialFingerprints": {"agentguardCase": case.case_id},
                "properties": {
                    "severity": case.severity.value,
                    "security-severity": _SECURITY_SEVERITY[case.severity],
                    "violationRate": round(case.violation_rate, 4),
                    "ciLow": round(case.ci_low, 4),
                    "ciHigh": round(case.ci_high, 4),
                    "owasp": case.owasp_llm,
                },
            }
        )
    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentGuard",
                        "version": result.agentguard_version,
                        "informationUri": "https://github.com/PiyushDas-2004/agentguard",
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": f"agentguard/{result.name}/{result.run_id}"},
                "results": results,
                "properties": {"riskScore": result.risk_score, "grade": result.grade, "partial": result.partial},
            }
        ],
    }


def render_sarif(result: RunResult, *, config_path: str = "agentguard.yaml") -> str:
    """Serialize the SARIF log."""
    return json.dumps(build_sarif(result, config_path=config_path), indent=2)
