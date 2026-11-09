"""Optional RAGAS backend (``agentguard[ragas]``).

RAGAS metrics (faithfulness, answer_relevancy, context_precision, context_recall) need an LLM, so
the backend runs only in live mode; offline it is skipped with an explanatory message.
"""

from __future__ import annotations

import importlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

__all__ = ["RAGAS_METRICS", "BackendResult", "RagSample", "evaluate_ragas", "ragas_available"]

RAGAS_METRICS = ("faithfulness", "answer_relevancy", "context_precision", "context_recall")


@dataclass(frozen=True)
class RagSample:
    """One RAG interaction for external evaluators."""

    question: str
    answer: str
    contexts: list[str]
    reference: str


@dataclass
class BackendResult:
    """Scores (metric -> mean) or a skip message."""

    scores: dict[str, float]
    message: str = ""


def ragas_available() -> tuple[bool, str]:
    """Whether the ``ragas`` package can be imported."""
    try:
        importlib.import_module("ragas")
    except ImportError:
        return False, "ragas backend skipped: package not installed (pip install 'agentguard[ragas]')"
    return True, ""


def _mean_scores(result: Any) -> dict[str, float]:
    rows = getattr(result, "scores", None)
    if isinstance(rows, list) and rows:
        out: dict[str, float] = {}
        for metric in rows[0]:
            values = [float(r[metric]) for r in rows if r.get(metric) is not None]
            if values:
                out[metric] = round(sum(values) / len(values), 4)
        return out
    return {str(k): round(float(v), 4) for k, v in dict(result).items()}


def evaluate_ragas(samples: Sequence[RagSample], *, offline: bool) -> BackendResult:
    """Score ``samples`` with RAGAS, or explain why the backend was skipped."""
    ok, message = ragas_available()
    if not ok:
        return BackendResult({}, message)
    if offline:
        return BackendResult({}, "ragas backend skipped: offline mode (RAGAS metrics require an LLM)")
    if not samples:
        return BackendResult({}, "ragas backend skipped: no RAG samples")
    ragas = importlib.import_module("ragas")
    metrics_module = importlib.import_module("ragas.metrics")
    dataset = ragas.EvaluationDataset.from_list(
        [
            {"user_input": s.question, "response": s.answer, "retrieved_contexts": s.contexts, "reference": s.reference}
            for s in samples
        ]
    )
    metrics = [getattr(metrics_module, name) for name in RAGAS_METRICS]
    result = ragas.evaluate(dataset=dataset, metrics=metrics)
    return BackendResult(_mean_scores(result))
