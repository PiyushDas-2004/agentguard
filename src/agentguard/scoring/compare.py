"""Compare two runs: new failures, fixes, risk delta, significant per-case/category changes."""

from __future__ import annotations

from pydantic import BaseModel, Field

from agentguard.core.types import CaseStatus, RunResult

__all__ = ["CaseChange", "CategoryDelta", "RunComparison", "compare_runs", "intervals_overlap"]


def intervals_overlap(a: tuple[float, float], b: tuple[float, float]) -> bool:
    """True if closed intervals ``a`` and ``b`` overlap."""
    return a[0] <= b[1] and b[0] <= a[1]


class CaseChange(BaseModel):
    """Change of one case between run A and run B."""

    case_id: str
    category: str
    status_a: str
    status_b: str
    rate_a: float
    rate_b: float
    significant: bool


class CategoryDelta(BaseModel):
    """Change of one category's pooled violation rate."""

    category: str
    rate_a: float
    rate_b: float
    delta: float
    significant: bool


class RunComparison(BaseModel):
    """Result of :func:`compare_runs`."""

    run_a: str
    run_b: str
    risk_a: float
    risk_b: float
    risk_delta: float
    grade_a: str
    grade_b: str
    new_failures: list[str] = Field(default_factory=list)
    fixed: list[str] = Field(default_factory=list)
    only_in_a: list[str] = Field(default_factory=list)
    only_in_b: list[str] = Field(default_factory=list)
    changes: list[CaseChange] = Field(default_factory=list)
    categories: list[CategoryDelta] = Field(default_factory=list)

    @property
    def regressed(self) -> bool:
        """True when B introduces new failures or a significant category regression."""
        return bool(self.new_failures) or any(c.significant and c.delta > 0 for c in self.categories)


def compare_runs(a: RunResult, b: RunResult) -> RunComparison:
    """Diff run ``b`` against baseline run ``a``.

    A change is *significant* only when the two Wilson intervals do not overlap.
    """
    cases_a = {c.case_id: c for c in a.cases}
    cases_b = {c.case_id: c for c in b.cases}
    changes: list[CaseChange] = []
    new_failures: list[str] = []
    fixed: list[str] = []
    for case_id in sorted(cases_a.keys() & cases_b.keys()):
        ca, cb = cases_a[case_id], cases_b[case_id]
        if cb.status == CaseStatus.failed and ca.status != CaseStatus.failed:
            new_failures.append(case_id)
        if ca.status == CaseStatus.failed and cb.status != CaseStatus.failed:
            fixed.append(case_id)
        significant = not intervals_overlap((ca.ci_low, ca.ci_high), (cb.ci_low, cb.ci_high))
        if ca.status != cb.status or significant:
            changes.append(
                CaseChange(
                    case_id=case_id,
                    category=ca.category.value,
                    status_a=ca.status.value,
                    status_b=cb.status.value,
                    rate_a=ca.violation_rate,
                    rate_b=cb.violation_rate,
                    significant=significant,
                )
            )
    cats_a = {c.category: c for c in a.categories}
    cats_b = {c.category: c for c in b.categories}
    categories = [
        CategoryDelta(
            category=cat.value,
            rate_a=cats_a[cat].violation_rate,
            rate_b=cats_b[cat].violation_rate,
            delta=round(cats_b[cat].violation_rate - cats_a[cat].violation_rate, 6),
            significant=not intervals_overlap(
                (cats_a[cat].ci_low, cats_a[cat].ci_high), (cats_b[cat].ci_low, cats_b[cat].ci_high)
            ),
        )
        for cat in cats_a
        if cat in cats_b
    ]
    return RunComparison(
        run_a=a.run_id,
        run_b=b.run_id,
        risk_a=a.risk_score,
        risk_b=b.risk_score,
        risk_delta=round(b.risk_score - a.risk_score, 6),
        grade_a=a.grade,
        grade_b=b.grade,
        new_failures=new_failures,
        fixed=fixed,
        only_in_a=sorted(cases_a.keys() - cases_b.keys()),
        only_in_b=sorted(cases_b.keys() - cases_a.keys()),
        changes=changes,
        categories=categories,
    )
