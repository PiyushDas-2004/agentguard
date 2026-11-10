"""Self-contained HTML report (inline CSS/JS/SVG, no CDN, light+dark, mobile friendly)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from agentguard.attacks.registry import CATEGORY_INFO
from agentguard.core.types import AttackCategory, CaseResult, CaseStatus, RunResult, ToolCall, Transcript, Verdict
from agentguard.reporting.remediation import REMEDIATION
from agentguard.scoring.owasp import owasp_url

__all__ = ["Segment", "highlight_segments", "render_html"]


@dataclass(frozen=True)
class Segment:
    """A piece of message text, optionally highlighted as evidence."""

    text: str
    reason: str | None = None


def highlight_segments(text: str, spans: list[tuple[int, int, str]]) -> list[Segment]:
    """Split ``text`` into plain and highlighted segments (overlapping spans are merged)."""
    cleaned = sorted((max(0, s), min(len(text), e), r) for s, e, r in spans if e > s and s < len(text))
    merged: list[tuple[int, int, str]] = []
    for start, end, reason in cleaned:
        if merged and start <= merged[-1][1]:
            prev = merged[-1]
            merged[-1] = (prev[0], max(prev[1], end), prev[2] if reason in prev[2] else f"{prev[2]}; {reason}")
        else:
            merged.append((start, end, reason))
    segments: list[Segment] = []
    cursor = 0
    for start, end, reason in merged:
        if start > cursor:
            segments.append(Segment(text[cursor:start]))
        segments.append(Segment(text[start:end], reason))
        cursor = end
    if cursor < len(text):
        segments.append(Segment(text[cursor:]))
    return segments


def _tool_class(call: ToolCall) -> str:
    """CSS class of a tool call: executed despite a policy violation, blocked/denied, or allowed."""
    if call.is_approval_request:
        return "allowed" if call.approved else "blocked"
    if call.policy_violations and call.executed:
        return "violation"
    if not call.allowed or not call.executed:
        return "blocked"
    return "allowed"


def _transcript_view(transcript: Transcript, verdicts: list[Verdict], max_chars: int = 6000) -> dict[str, Any]:
    spans: dict[int, list[tuple[int, int, str]]] = {}
    for verdict in verdicts:
        if not verdict.violated:
            continue
        for ev in verdict.evidence:
            if ev.turn_index >= 0:
                spans.setdefault(ev.turn_index, []).append((ev.start, ev.end, f"{verdict.detector_id}: {ev.reason}"))
    turns = []
    for turn in transcript.turns:
        text = turn.content
        truncated = len(text) > max_chars
        shown = text[:max_chars]
        calls = [
            {
                "name": c.name,
                "args": ", ".join(f"{k}={str(v)[:120]!r}" for k, v in c.arguments.items()),
                "cls": _tool_class(c),
                "note": "; ".join(c.policy_violations)
                or ("approval requested: " + ("granted" if c.approved else "denied") if c.is_approval_request else ""),
                "result": c.result_preview[:240],
            }
            for c in transcript.tool_calls
            if turn.role.value == "assistant" and c.turn_index == turn.index and c.session == turn.session
        ]
        turns.append(
            {
                "role": turn.role.value,
                "session": turn.session,
                "segments": highlight_segments(shown, spans.get(turn.index, [])),
                "truncated": truncated,
                "chars": len(text),
                "calls": calls,
                "meta": f"{turn.tokens_in}+{turn.tokens_out} tok · {turn.latency_ms:.0f} ms"
                if turn.role.value == "assistant"
                else "",
            }
        )
    return {"turns": turns}


def _ci_bar(low: float, high: float, rate: float, width: int = 220) -> dict[str, float]:
    return {"x1": round(low * width, 2), "x2": round(high * width, 2), "cx": round(rate * width, 2), "w": width}


def _case_view(case: CaseResult) -> dict[str, Any]:
    return {
        "case": case,
        "bar": _ci_bar(case.ci_low, case.ci_high, case.violation_rate, 120),
        "samples": [
            {
                "sample": s,
                "view": _transcript_view(s.transcript, s.verdicts),
                "verdicts": [v for v in s.verdicts if v.violated or v.inconclusive],
            }
            for s in case.samples
        ],
    }


def render_html(result: RunResult) -> str:
    """Render the full HTML report for ``result``."""
    env = Environment(
        loader=PackageLoader("agentguard.reporting", "templates"),
        autoescape=select_autoescape(["html", "j2", "html.j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.html.j2")
    failed = [c for c in result.cases if c.status == CaseStatus.failed and c.category != AttackCategory.OVER_REFUSAL]
    top = sorted(failed, key=lambda c: (-c.severity.weight, -c.violation_rate, c.case_id))[:5]
    failed_categories = sorted({c.category for c in failed}, key=lambda c: list(AttackCategory).index(c))
    if any(c.status == CaseStatus.failed for c in result.cases if c.category == AttackCategory.OVER_REFUSAL):
        failed_categories.append(AttackCategory.OVER_REFUSAL)
    mutation_stats: dict[str, list[float]] = {}
    for case in result.cases:
        for mutation, rate in case.mutation_rates.items():
            mutation_stats.setdefault(mutation, []).append(rate)
    seed_rates = [c.seed_violation_rate for c in result.cases if c.seed_violation_rate is not None and c.mutation_rates]
    robustness = {
        "seed": sum(seed_rates) / len(seed_rates) if seed_rates else None,
        "by_transform": {m: sum(v) / len(v) for m, v in sorted(mutation_stats.items())},
        "regressions": sorted(
            (
                c
                for c in result.cases
                if c.mutated_violation_rate is not None
                and c.seed_violation_rate is not None
                and c.mutated_violation_rate > c.seed_violation_rate
            ),
            key=lambda c: c.seed_violation_rate - (c.mutated_violation_rate or 0),
        )[:10],
    }
    return template.render(
        r=result,
        top=top,
        categories=[
            {"card": c, "bar": _ci_bar(c.ci_low, c.ci_high, c.violation_rate), "title": CATEGORY_INFO[c.category].title}
            for c in result.categories
        ],
        cases=[_case_view(c) for c in sorted(result.cases, key=lambda c: c.case_id)],
        remediation=[
            {"category": c, "title": CATEGORY_INFO[c].title, "items": REMEDIATION[c]} for c in failed_categories
        ],
        owasp=[{"row": row, "url": owasp_url(row.owasp_id)} for row in result.owasp_coverage],
        robustness=robustness,
        gauge_angle=round(result.risk_score / 100 * 180, 2),
    )
