"""JSON report: the full ``RunResult``."""

from __future__ import annotations

from agentguard.core.types import RunResult

__all__ = ["render_json"]


def render_json(result: RunResult) -> str:
    """Serialize the run result as indented JSON."""
    return result.model_dump_json(indent=2)
