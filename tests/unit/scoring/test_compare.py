"""compare_runs and intervals_overlap."""

from __future__ import annotations

import pytest

from agentguard.core.types import AttackCategory, CaseStatus
from agentguard.scoring.compare import compare_runs, intervals_overlap
from tests.unit.scoring._builders import case_result, run_result


@pytest.mark.parametrize(
    ("a", "b", "overlap"),
    [
        ((0.0, 0.3), (0.2, 0.5), True),
        ((0.0, 0.3), (0.3, 0.5), True),  # touching closed intervals overlap
        ((0.0, 0.3), (0.31, 0.5), False),
        ((0.4, 0.6), (0.0, 0.39), False),
        ((0.1, 0.9), (0.4, 0.5), True),  # containment
        ((0.2, 0.2), (0.2, 0.2), True),
    ],
)
def test_intervals_overlap(a: tuple[float, float], b: tuple[float, float], overlap: bool) -> None:
    assert intervals_overlap(a, b) is overlap
    assert intervals_overlap(b, a) is overlap


def test_new_failures_fixed_and_only_in() -> None:
    a = run_result(
        "A",
        [
            case_result("C-001", k=0, n=40),  # pass -> fail
            case_result("C-002", k=40, n=40),  # fail -> pass
            case_result("C-003", k=40, n=40),  # fail -> fail
            case_result("C-004", k=0, n=40),  # only in A
        ],
    )
    b = run_result(
        "B",
        [
            case_result("C-001", k=40, n=40),
            case_result("C-002", k=0, n=40),
            case_result("C-003", k=40, n=40),
            case_result("C-005", k=0, n=40),  # only in B
        ],
    )
    cmp = compare_runs(a, b)
    assert (cmp.run_a, cmp.run_b) == ("A", "B")
    assert cmp.new_failures == ["C-001"]
    assert cmp.fixed == ["C-002"]
    assert cmp.only_in_a == ["C-004"]
    assert cmp.only_in_b == ["C-005"]
    assert [c.case_id for c in cmp.changes] == ["C-001", "C-002"]
    change = cmp.changes[0]
    assert (change.status_a, change.status_b, change.rate_a, change.rate_b) == ("pass", "fail", 0.0, 1.0)
    assert change.significant
    assert change.category == "PI_DIRECT"
    assert cmp.regressed
    assert cmp.risk_delta == pytest.approx(round(b.risk_score - a.risk_score, 6))
    assert (cmp.grade_a, cmp.grade_b) == (a.grade, b.grade)


def test_status_change_without_significance() -> None:
    # 1/10 (inconclusive) vs 3/10 (fail): status differs but intervals overlap.
    a = run_result("A", [case_result("C-001", k=1, n=10)])
    b = run_result("B", [case_result("C-001", k=3, n=10)])
    cmp = compare_runs(a, b)
    assert [(c.status_a, c.status_b, c.significant) for c in cmp.changes] == [("inconclusive", "fail", False)]
    assert cmp.new_failures == ["C-001"]
    assert cmp.categories[0].significant is False
    assert cmp.regressed  # new failure


def test_significant_change_with_same_status() -> None:
    # Both fail, but 15/40 vs 40/40 do not overlap -> reported as a significant change.
    a = run_result("A", [case_result("C-001", k=15, n=40)])
    b = run_result("B", [case_result("C-001", k=40, n=40)])
    assert a.cases[0].status == b.cases[0].status == CaseStatus.failed
    cmp = compare_runs(a, b)
    assert len(cmp.changes) == 1
    assert cmp.changes[0].significant
    assert cmp.new_failures == []
    assert cmp.categories[0].significant
    assert cmp.categories[0].delta == pytest.approx(25 / 40)
    assert cmp.regressed  # significant category regression


def test_significant_improvement_is_not_a_regression() -> None:
    a = run_result("A", [case_result("C-001", k=40, n=40)])
    b = run_result("B", [case_result("C-001", k=15, n=40)])
    cmp = compare_runs(a, b)
    assert cmp.categories[0].significant
    assert cmp.categories[0].delta < 0
    assert not cmp.regressed


def test_identical_runs() -> None:
    cases = [case_result("C-001", k=2, n=10), case_result("C-002", k=0, n=40, category=AttackCategory.JAILBREAK)]
    cmp = compare_runs(run_result("A", cases), run_result("B", cases))
    assert cmp.changes == []
    assert cmp.new_failures == cmp.fixed == cmp.only_in_a == cmp.only_in_b == []
    assert [c.delta for c in cmp.categories] == [0.0, 0.0]
    assert cmp.risk_delta == 0.0
    assert not cmp.regressed


def test_categories_only_compared_when_in_both_runs() -> None:
    a = run_result("A", [case_result("C-001", k=0, n=40, category=AttackCategory.PII_LEAK)])
    b = run_result("B", [case_result("C-002", k=0, n=40, category=AttackCategory.JAILBREAK)])
    cmp = compare_runs(a, b)
    assert cmp.categories == []
    assert cmp.only_in_a == ["C-001"] and cmp.only_in_b == ["C-002"]
    assert not cmp.regressed


def test_comparison_round_trips_json() -> None:
    a = run_result("A", [case_result("C-001", k=0, n=40)])
    b = run_result("B", [case_result("C-001", k=40, n=40)])
    cmp = compare_runs(a, b)
    assert type(cmp).model_validate_json(cmp.model_dump_json()) == cmp
