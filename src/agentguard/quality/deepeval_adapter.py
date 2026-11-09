"""Optional DeepEval backend (``agentguard[deepeval]``): GEval, Hallucination, Toxicity, Bias.

DeepEval metrics use an LLM evaluator, so the backend runs only in live mode.
"""

from __future__ import annotations

import importlib
from collections.abc import Sequence
from typing import Any

from agentguard.quality.ragas_adapter import BackendResult, RagSample

__all__ = ["DEEPEVAL_METRICS", "deepeval_available", "evaluate_deepeval"]

DEEPEVAL_METRICS = ("geval_correctness", "hallucination", "toxicity", "bias")


def deepeval_available() -> tuple[bool, str]:
    """Whether the ``deepeval`` package can be imported."""
    try:
        importlib.import_module("deepeval")
    except ImportError:
        return False, "deepeval backend skipped: package not installed (pip install 'agentguard[deepeval]')"
    return True, ""


def _metrics(module: Any, test_case_params: Any) -> dict[str, Any]:
    return {
        "geval_correctness": module.GEval(
            name="Correctness",
            criteria="Is the actual output factually consistent with the expected output?",
            evaluation_params=[test_case_params.ACTUAL_OUTPUT, test_case_params.EXPECTED_OUTPUT],
        ),
        "hallucination": module.HallucinationMetric(threshold=0.5),
        "toxicity": module.ToxicityMetric(threshold=0.5),
        "bias": module.BiasMetric(threshold=0.5),
    }


def evaluate_deepeval(samples: Sequence[RagSample], *, offline: bool) -> BackendResult:
    """Score ``samples`` with DeepEval metrics, or explain why the backend was skipped."""
    ok, message = deepeval_available()
    if not ok:
        return BackendResult({}, message)
    if offline:
        return BackendResult({}, "deepeval backend skipped: offline mode (DeepEval metrics require an LLM)")
    if not samples:
        return BackendResult({}, "deepeval backend skipped: no samples")
    metrics_module = importlib.import_module("deepeval.metrics")
    test_case_module = importlib.import_module("deepeval.test_case")
    metrics = _metrics(metrics_module, test_case_module.LLMTestCaseParams)
    totals: dict[str, list[float]] = {name: [] for name in metrics}
    for sample in samples:
        case = test_case_module.LLMTestCase(
            input=sample.question,
            actual_output=sample.answer,
            expected_output=sample.reference,
            context=sample.contexts,
            retrieval_context=sample.contexts,
        )
        for name, metric in metrics.items():
            metric.measure(case)
            totals[name].append(float(metric.score))
    return BackendResult({name: round(sum(v) / len(v), 4) for name, v in totals.items() if v})
