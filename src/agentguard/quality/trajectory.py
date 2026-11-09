"""Tool-trajectory metrics: exact / in-order / any-order match, precision/recall/F1, arguments."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from agentguard.core.types import ToolCall
from agentguard.quality.datasets import ExpectedCall

__all__ = ["TrajectoryScore", "call_matches", "score_trajectory"]


def call_matches(expected: ExpectedCall, actual: ToolCall) -> bool:
    """Same tool name and every expected argument regex matches ``str(actual value)``."""
    if expected.tool != actual.name:
        return False
    return all(re.search(rx, str(actual.arguments.get(arg, "")), re.I) for arg, rx in expected.args.items())


@dataclass(frozen=True)
class TrajectoryScore:
    """Per-task trajectory metrics."""

    exact_match: bool
    in_order_match: bool
    any_order_match: bool
    precision: float
    recall: float
    f1: float
    argument_correctness: float
    unnecessary_calls: int


def score_trajectory(expected: Sequence[ExpectedCall], actual: Sequence[ToolCall]) -> TrajectoryScore:
    """Score the actual tool calls of one task run against its expected trajectory."""
    calls = [c for c in actual if not c.is_approval_request]
    exact = len(expected) == len(calls) and all(call_matches(e, a) for e, a in zip(expected, calls, strict=False))
    position = 0
    for call in calls:
        if position < len(expected) and call_matches(expected[position], call):
            position += 1
    in_order = position == len(expected)
    used: set[int] = set()
    for exp in expected:
        for i, call in enumerate(calls):
            if i not in used and call_matches(exp, call):
                used.add(i)
                break
    any_order = len(used) == len(expected)
    remaining = [e.tool for e in expected]
    name_hits = 0
    for call in calls:
        if call.name in remaining:
            remaining.remove(call.name)
            name_hits += 1
    precision = name_hits / len(calls) if calls else (1.0 if not expected else 0.0)
    recall = name_hits / len(expected) if expected else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    relevant = [c for c in calls if any(e.tool == c.name for e in expected)]
    args_ok = sum(1 for c in relevant if any(call_matches(e, c) for e in expected))
    argument_correctness = args_ok / len(relevant) if relevant else (1.0 if not expected else 0.0)
    expected_names = {e.tool for e in expected}
    unnecessary = sum(1 for c in calls if c.name not in expected_names) + max(0, len(relevant) - len(expected))
    return TrajectoryScore(
        exact,
        in_order,
        any_order,
        round(precision, 4),
        round(recall, 4),
        round(f1, 4),
        round(argument_correctness, 4),
        unnecessary,
    )
