"""Performance statistics: latency percentiles, tokens, cost per task, error rate."""

from __future__ import annotations

from collections.abc import Sequence

from agentguard.core.types import PerformanceReport, Role, Trial
from agentguard.scoring.stats import percentile

__all__ = ["performance_report"]


def performance_report(trials: Sequence[Trial]) -> PerformanceReport:
    """Summarize latency (per assistant turn), tokens, cost and errors over ``trials``."""
    latencies = [t.latency_ms for trial in trials for t in trial.transcript.turns if t.role == Role.assistant]
    cost = sum(trial.transcript.cost_usd for trial in trials)
    errors = sum(1 for trial in trials if trial.error is not None)
    return PerformanceReport(
        n_calls=len(latencies),
        latency_p50_ms=round(percentile(latencies, 50), 3),
        latency_p95_ms=round(percentile(latencies, 95), 3),
        latency_p99_ms=round(percentile(latencies, 99), 3),
        tokens_in=sum(trial.transcript.tokens_in for trial in trials),
        tokens_out=sum(trial.transcript.tokens_out for trial in trials),
        cost_usd=round(cost, 8),
        cost_per_task_usd=round(cost / len(trials), 10) if trials else 0.0,
        error_rate=round(errors / len(trials), 4) if trials else 0.0,
    )
