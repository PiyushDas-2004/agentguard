"""Deterministic task-success checks (judge fallback handled by the suite)."""

from __future__ import annotations

import re
from collections.abc import Sequence

from agentguard.core.types import ToolCall
from agentguard.quality.datasets import QualityTask

__all__ = ["check_success"]


def check_success(task: QualityTask, reply: str, calls: Sequence[ToolCall]) -> bool | None:
    """Return True/False for deterministic checks, ``None`` when a judge is required."""
    check = task.success
    if check.type == "output_contains":
        return check.value.lower() in reply.lower()
    if check.type == "output_regex":
        return bool(re.search(check.value, reply, re.I | re.S))
    if check.type == "tool_called":
        return any(c.name == check.value and c.executed and not c.is_approval_request for c in calls)
    return None
