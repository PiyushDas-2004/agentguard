"""Wilson score interval and percentile, checked against hand-computed values (z = 1.96)."""

from __future__ import annotations

import pytest

from agentguard.scoring.stats import DEFAULT_Z, percentile, wilson_interval

# With z = 1.96: z² = 3.8416.
#   denom  = 1 + z²/n
#   center = (p + z²/(2n)) / denom
#   margin = z * sqrt(p(1-p)/n + z²/(4n²)) / denom


def test_default_z() -> None:
    assert DEFAULT_Z == 1.96


def test_k0_n5() -> None:
    # p = 0; denom = 1 + 3.8416/5 = 1.76832
    # center = (0 + 3.8416/10) / 1.76832 = 0.38416 / 1.76832 = 0.2172457
    # margin = 1.96 * sqrt(0 + 3.8416/100) / 1.76832 = 1.96 * 0.196 / 1.76832 = 0.38416 / 1.76832 = 0.2172457
    # low = max(0, 0.2172457 - 0.2172457) = 0 ; high = 0.4344915
    low, high = wilson_interval(0, 5)
    assert low == 0.0
    assert high == pytest.approx(0.4344915, abs=1e-6)


def test_k5_n5() -> None:
    # p = 1; center = (1 + 0.38416) / 1.76832 = 0.7827543 ; margin = 0.2172457 (p(1-p) = 0 as above)
    # low = 0.7827543 - 0.2172457 = 0.5655085 ; high = min(1, 1.0) = 1
    low, high = wilson_interval(5, 5)
    assert low == pytest.approx(0.5655085, abs=1e-6)
    assert high == 1.0


def test_k2_n5() -> None:
    # p = 0.4; center = (0.4 + 0.38416) / 1.76832 = 0.78416 / 1.76832 = 0.4434493
    # p(1-p)/n = 0.24/5 = 0.048 ; z²/(4n²) = 3.8416/100 = 0.038416 ; sum = 0.086416
    # sqrt(0.086416) = 0.2939660 ; margin = 1.96 * 0.2939660 / 1.76832 = 0.5761733 / 1.76832 = 0.3258311
    # low = 0.4434493 - 0.3258311 = 0.1176182 ; high = 0.4434493 + 0.3258311 = 0.7692801
    low, high = wilson_interval(2, 5)
    assert low == pytest.approx(0.1176182, abs=1e-6)
    assert high == pytest.approx(0.7692801, abs=1e-6)


def test_k10_n20() -> None:
    # p = 0.5; denom = 1 + 3.8416/20 = 1.19208
    # center = (0.5 + 3.8416/40) / 1.19208 = 0.59604 / 1.19208 = 0.5
    # p(1-p)/n = 0.25/20 = 0.0125 ; z²/(4n²) = 3.8416/1600 = 0.002401 ; sum = 0.014901
    # sqrt(0.014901) = 0.1220697 ; margin = 1.96 * 0.1220697 / 1.19208 = 0.2392566 / 1.19208 = 0.2007051
    # low = 0.2992949 ; high = 0.7007051
    low, high = wilson_interval(10, 20)
    assert low == pytest.approx(0.2992949, abs=1e-6)
    assert high == pytest.approx(0.7007051, abs=1e-6)
    assert (low + high) / 2 == pytest.approx(0.5)  # symmetric around p = 0.5


def test_n0_is_uninformative() -> None:
    assert wilson_interval(0, 0) == (0.0, 1.0)


def test_custom_z_widens_interval() -> None:
    narrow = wilson_interval(3, 10, z=1.0)
    wide = wilson_interval(3, 10, z=2.576)
    assert wide[0] < narrow[0] < 0.3 < narrow[1] < wide[1]


def test_z_zero_collapses_to_point_estimate() -> None:
    assert wilson_interval(3, 10, z=0.0) == pytest.approx((0.3, 0.3))


@pytest.mark.parametrize(("k", "n"), [(-1, 5), (6, 5), (0, -1), (1, 0)])
def test_invalid_counts(k: int, n: int) -> None:
    with pytest.raises(ValueError, match="invalid counts"):
        wilson_interval(k, n)


@pytest.mark.parametrize(
    ("values", "q", "expected"),
    [
        ([], 50, 0.0),
        ([7], 99, 7.0),
        ([1, 2, 3, 4], 0, 1.0),
        ([1, 2, 3, 4], 100, 4.0),
        ([4, 1, 3, 2], 50, 2.5),  # rank = 3 * 0.5 = 1.5 -> 2 + (3-2)*0.5
        ([10, 20, 30, 40, 50], 50, 30.0),  # rank = 2 exactly
        ([10, 20, 30, 40, 50], 95, 48.0),  # rank = 3.8 -> 40 + 10*0.8
        ([0.0, 100.0], 99, 99.0),
    ],
)
def test_percentile(values: list[float], q: float, expected: float) -> None:
    assert percentile(values, q) == pytest.approx(expected)


@pytest.mark.parametrize("q", [-0.1, 100.1])
def test_percentile_rejects_bad_q(q: float) -> None:
    with pytest.raises(ValueError, match="q must be"):
        percentile([1.0, 2.0], q)


def test_percentile_empty_ignores_q() -> None:
    assert percentile([], 500) == 0.0
