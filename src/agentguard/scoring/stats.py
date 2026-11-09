"""Wilson score interval and percentile helpers."""

from __future__ import annotations

import math
from collections.abc import Sequence

__all__ = ["DEFAULT_Z", "percentile", "wilson_interval"]

DEFAULT_Z = 1.96


def wilson_interval(k: int, n: int, z: float = DEFAULT_Z) -> tuple[float, float]:
    """Wilson score interval for ``k`` successes in ``n`` trials.

    ``center = (p + z²/2n) / (1 + z²/n)``;
    ``margin = z·sqrt(p(1-p)/n + z²/4n²) / (1 + z²/n)``.

    Args:
        k: number of violations (0 <= k <= n).
        n: number of trials (0 gives the uninformative interval (0, 1)).
        z: normal quantile (1.96 for 95%).

    Returns:
        ``(low, high)`` clipped to [0, 1].

    Raises:
        ValueError: if ``k`` is outside ``[0, n]`` or ``n`` is negative.
    """
    if n < 0 or k < 0 or k > n:
        raise ValueError(f"invalid counts k={k}, n={n}")
    if n == 0:
        return 0.0, 1.0
    p = k / n
    z2 = z * z
    denom = 1 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    margin = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
    low = max(0.0, center - margin)
    high = min(1.0, center + margin)
    # Guard floating-point drift so low <= p <= high always holds.
    return min(low, p), max(high, p)


def percentile(values: Sequence[float], q: float) -> float:
    """Linear-interpolated percentile (``q`` in [0, 100]); 0.0 for an empty sequence."""
    if not values:
        return 0.0
    if not 0 <= q <= 100:
        raise ValueError("q must be in [0, 100]")
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (len(ordered) - 1) * q / 100
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return float(ordered[lower])
    fraction = rank - lower
    return float(ordered[lower] + (ordered[upper] - ordered[lower]) * fraction)
