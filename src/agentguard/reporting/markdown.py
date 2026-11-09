"""Markdown summary suitable for pull-request comments."""

from __future__ import annotations

from agentguard.core.types import CaseStatus, RunResult

__all__ = ["render_markdown"]


def render_markdown(result: RunResult, *, max_failures: int = 10) -> str:
    """Render a compact Markdown summary."""
    verdict = "PASSED" if result.passed_threshold else "FAILED"
    icon = "✅" if result.passed_threshold else "❌"
    lines = [
        f"## {icon} AgentGuard: {result.name} — {verdict}",
        "",
        f"**Risk score:** {result.risk_score:.1f} / 100 (grade **{result.grade}**, threshold {result.fail_threshold_risk:g})",
        f"**Target:** `{result.target.type}` {result.target.name}  ",
        f"**Trials:** {result.total_trials} ({result.total_errors} errors) · **Cost:** ${result.total_cost_usd:.4f} · "
        f"**Duration:** {result.duration_s:.1f}s",
    ]
    if result.over_refusal_rate is not None:
        lines.append(f"**Over-refusal rate:** {result.over_refusal_rate:.1%}")
    if result.partial:
        lines.append(f"> ⚠️ Partial run ({result.abort_reason}).")
    lines += [
        "",
        "| Category | Cases | Fail | Pass | Inconclusive | Violation rate (95% CI) |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for card in result.categories:
        lines.append(
            f"| {card.category.value} | {card.n_cases} | {card.n_fail} | {card.n_pass} | {card.n_inconclusive} | "
            f"{card.violation_rate:.0%} ({card.ci_low:.2f}–{card.ci_high:.2f}) |"
        )
    failures = sorted(
        (c for c in result.cases if c.status == CaseStatus.failed), key=lambda c: (-c.risk_contribution, c.case_id)
    )
    if failures:
        lines += ["", f"### Top failures ({len(failures)} total)", ""]
        for case in failures[:max_failures]:
            lines.append(
                f"- **{case.case_id}** ({case.severity.value}) {case.title} — "
                f"{case.n_violations}/{case.n_trials} trials"
            )
    if result.quality is not None and result.quality.task_success_rate is not None:
        lines += [
            "",
            f"**Quality:** task success {result.quality.task_success_rate:.0%}"
            + (f", RAG faithfulness {result.quality.rag.get('faithfulness', 0):.2f}" if result.quality.rag else ""),
        ]
    lines += ["", f"<sub>AgentGuard {result.agentguard_version} · run `{result.run_id}` · seed {result.seed}</sub>"]
    return "\n".join(lines) + "\n"
