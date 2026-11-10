"""Property tests for the Wilson interval, risk score and grade."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from agentguard.core.types import AttackCategory, Severity
from agentguard.scoring.aggregate import category_scorecards
from agentguard.scoring.risk import grade, overall_risk
from agentguard.scoring.stats import wilson_interval
from tests.unit.scoring._builders import case_result

GRADE_ORDER = "ABCDF"


@st.composite
def counts(draw: st.DrawFn, max_n: int = 5000) -> tuple[int, int]:
    n = draw(st.integers(min_value=0, max_value=max_n))
    k = draw(st.integers(min_value=0, max_value=n))
    return k, n


@st.composite
def case_specs(draw: st.DrawFn) -> tuple[int, int, Severity, AttackCategory]:
    k, n = draw(counts(max_n=200))
    return k, n, draw(st.sampled_from(list(Severity))), draw(st.sampled_from(list(AttackCategory)))


def _results(specs: list[tuple[int, int, Severity, AttackCategory]]):  # type: ignore[no-untyped-def]
    return [case_result(f"C-{i:03d}", k=k, n=n, severity=sev, category=cat) for i, (k, n, sev, cat) in enumerate(specs)]


@given(kn=counts(), z=st.floats(min_value=0.0, max_value=6.0))
def test_wilson_bounds_in_unit_interval_and_bracket_p(kn: tuple[int, int], z: float) -> None:
    k, n = kn
    low, high = wilson_interval(k, n, z)
    assert 0.0 <= low <= high <= 1.0
    if n:
        assert low <= k / n <= high


@given(kn=counts())
def test_wilson_monotonic_in_k(kn: tuple[int, int]) -> None:
    k, n = kn
    if k < n:
        low_a, high_a = wilson_interval(k, n)
        low_b, high_b = wilson_interval(k + 1, n)
        assert low_a <= low_b
        assert high_a <= high_b


@given(kn=counts())
def test_wilson_symmetry(kn: tuple[int, int]) -> None:
    k, n = kn
    low, high = wilson_interval(k, n)
    low_c, high_c = wilson_interval(n - k, n)
    assert abs(low - (1 - high_c)) < 1e-9
    assert abs(high - (1 - low_c)) < 1e-9


@given(specs=st.lists(case_specs(), min_size=1, max_size=12), data=st.data())
def test_risk_non_decreasing_when_a_case_gains_violations(specs, data) -> None:  # type: ignore[no-untyped-def]
    index = data.draw(st.integers(min_value=0, max_value=len(specs) - 1))
    k, n, sev, cat = specs[index]
    extra = data.draw(st.integers(min_value=0, max_value=n - k))
    worse = list(specs)
    worse[index] = (k + extra, n, sev, cat)
    assert overall_risk(_results(worse)) >= overall_risk(_results(specs))


@given(specs=st.lists(case_specs(), max_size=12), data=st.data())
def test_risk_invariant_to_case_order(specs, data) -> None:  # type: ignore[no-untyped-def]
    results = _results(specs)
    shuffled = data.draw(st.permutations(results))
    assert overall_risk(shuffled) == overall_risk(results)


@given(specs=st.lists(case_specs(), max_size=12))
def test_risk_bounded_and_gradeable(specs) -> None:  # type: ignore[no-untyped-def]
    results = _results(specs)
    risk = overall_risk(results)
    assert 0.0 <= risk <= 100.0
    assert grade(risk) in GRADE_ORDER
    for card in category_scorecards(results):
        assert 0.0 <= card.risk <= 100.0
        assert 0.0 <= card.ci_low <= card.violation_rate <= card.ci_high <= 1.0


@given(
    a=st.floats(min_value=0.0, max_value=100.0, allow_nan=False),
    b=st.floats(min_value=0.0, max_value=100.0, allow_nan=False),
)
def test_grade_monotonic_in_risk(a: float, b: float) -> None:
    low, high = sorted((a, b))
    assert GRADE_ORDER.index(grade(low)) <= GRADE_ORDER.index(grade(high))
