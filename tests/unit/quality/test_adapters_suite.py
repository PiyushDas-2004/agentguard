"""RAGAS / DeepEval adapters (stub modules injected) and the quality-suite orchestration."""

from __future__ import annotations

import asyncio
import sys
import types
from pathlib import Path
from typing import Any

import pytest
import yaml

from agentguard.config.models import QualitySuiteConfig
from agentguard.config.policy import Policy
from agentguard.core.errors import BudgetExceededError
from agentguard.harness.conversation import ConversationDriver
from agentguard.harness.rag_fixture import RagCorpus
from agentguard.judges.mock_judge import MockJudge
from agentguard.quality import deepeval_adapter, ragas_adapter
from agentguard.quality.deepeval_adapter import DEEPEVAL_METRICS, deepeval_available, evaluate_deepeval
from agentguard.quality.ragas_adapter import (
    RAGAS_METRICS,
    BackendResult,
    RagSample,
    _mean_scores,
    evaluate_ragas,
    ragas_available,
)
from agentguard.quality.suite import carrier_case, run_quality_suite
from agentguard.targets.python_callable import PythonCallableTarget

SAMPLES = [
    RagSample("q1", "a1", ["c1"], "r1"),
    RagSample("q2", "a2", ["c2"], "r2"),
]


# --------------------------------------------------------------------------- stubs of external libs


def install_ragas(monkeypatch: pytest.MonkeyPatch, result: Any) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    ragas = types.ModuleType("ragas")
    metrics = types.ModuleType("ragas.metrics")
    for name in RAGAS_METRICS:
        setattr(metrics, name, f"metric:{name}")

    class EvaluationDataset:
        @staticmethod
        def from_list(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
            seen["rows"] = rows
            return rows

    def evaluate(dataset: Any, metrics: list[Any]) -> Any:
        seen["metrics"] = metrics
        return result

    ragas.EvaluationDataset = EvaluationDataset  # type: ignore[attr-defined]
    ragas.evaluate = evaluate  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "ragas", ragas)
    monkeypatch.setitem(sys.modules, "ragas.metrics", metrics)
    return seen


def install_deepeval(monkeypatch: pytest.MonkeyPatch, scores: dict[str, list[float]]) -> list[Any]:
    cases: list[Any] = []
    deepeval = types.ModuleType("deepeval")
    metrics = types.ModuleType("deepeval.metrics")
    test_case = types.ModuleType("deepeval.test_case")

    def metric_class(key: str) -> type:
        class Metric:
            def __init__(self, **kwargs: Any) -> None:
                self.kwargs = kwargs
                self.score = 0.0
                self._scores = list(scores[key])

            def measure(self, case: Any) -> None:
                self.score = self._scores.pop(0)

        return Metric

    metrics.GEval = metric_class("geval_correctness")  # type: ignore[attr-defined]
    metrics.HallucinationMetric = metric_class("hallucination")  # type: ignore[attr-defined]
    metrics.ToxicityMetric = metric_class("toxicity")  # type: ignore[attr-defined]
    metrics.BiasMetric = metric_class("bias")  # type: ignore[attr-defined]

    class LLMTestCaseParams:
        ACTUAL_OUTPUT = "actual_output"
        EXPECTED_OUTPUT = "expected_output"

    class LLMTestCase:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs
            cases.append(self)

    test_case.LLMTestCaseParams = LLMTestCaseParams  # type: ignore[attr-defined]
    test_case.LLMTestCase = LLMTestCase  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "deepeval", deepeval)
    monkeypatch.setitem(sys.modules, "deepeval.metrics", metrics)
    monkeypatch.setitem(sys.modules, "deepeval.test_case", test_case)
    return cases


class TestRagasAdapter:
    def test_not_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "ragas", None)
        ok, message = ragas_available()
        assert not ok
        assert "package not installed" in message
        assert "agentguard[ragas]" in message
        result = evaluate_ragas(SAMPLES, offline=False)
        assert result.scores == {}
        assert result.message == message

    def test_offline(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_ragas(monkeypatch, {})
        assert ragas_available() == (True, "")
        result = evaluate_ragas(SAMPLES, offline=True)
        assert result == BackendResult({}, "ragas backend skipped: offline mode (RAGAS metrics require an LLM)")

    def test_no_samples(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_ragas(monkeypatch, {})
        assert evaluate_ragas([], offline=False).message == "ragas backend skipped: no RAG samples"

    def test_scores_rows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        result_obj = types.SimpleNamespace(
            scores=[
                {"faithfulness": 1.0, "answer_relevancy": 0.5},
                {"faithfulness": 0.5, "answer_relevancy": None},
            ]
        )
        seen = install_ragas(monkeypatch, result_obj)
        result = evaluate_ragas(SAMPLES, offline=False)
        assert result.scores == {"faithfulness": 0.75, "answer_relevancy": 0.5}
        assert result.message == ""
        assert seen["metrics"] == [f"metric:{m}" for m in RAGAS_METRICS]
        assert seen["rows"][0] == {
            "user_input": "q1",
            "response": "a1",
            "retrieved_contexts": ["c1"],
            "reference": "r1",
        }

    def test_scores_mapping_fallback(self) -> None:
        assert _mean_scores({"faithfulness": 0.12345}) == {"faithfulness": 0.1235}
        assert _mean_scores(types.SimpleNamespace(scores=[{"x": None}], keys=lambda: [])) == {}


class TestDeepEvalAdapter:
    def test_not_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "deepeval", None)
        ok, message = deepeval_available()
        assert not ok
        assert "agentguard[deepeval]" in message
        assert evaluate_deepeval(SAMPLES, offline=False).message == message

    def test_offline_and_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        install_deepeval(monkeypatch, {})
        assert deepeval_available() == (True, "")
        assert "offline mode" in evaluate_deepeval(SAMPLES, offline=True).message
        assert evaluate_deepeval([], offline=False).message == "deepeval backend skipped: no samples"

    def test_scores(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cases = install_deepeval(
            monkeypatch,
            {
                "geval_correctness": [1.0, 0.5],
                "hallucination": [0.0, 0.2],
                "toxicity": [0.0, 0.0],
                "bias": [0.1, 0.3],
            },
        )
        result = evaluate_deepeval(SAMPLES, offline=False)
        assert set(result.scores) == set(DEEPEVAL_METRICS)
        assert result.scores == {"geval_correctness": 0.75, "hallucination": 0.1, "toxicity": 0.0, "bias": 0.2}
        assert len(cases) == 2
        assert cases[0].kwargs == {
            "input": "q1",
            "actual_output": "a1",
            "expected_output": "r1",
            "context": ["c1"],
            "retrieval_context": ["c1"],
        }

    def test_modules_share_backend_result(self) -> None:
        assert deepeval_adapter.BackendResult is ragas_adapter.BackendResult


# --------------------------------------------------------------------------- quality suite


class QualityAgent:
    """Deterministic agent: looks up orders, searches docs, otherwise answers plainly."""

    async def __call__(self, conversation: list[Any], tools: Any, context: Any) -> dict[str, Any]:
        question = conversation[-1].content
        if "O-2002" in question:
            result = await tools.call("db_query", {"table": "orders", "where": {"id": "O-2002"}})
            return {"text": result.content}
        if "refund" in question.lower():
            result = await tools.call("search_docs", {"query": question})
            if "contexts" in question:
                return {"text": "Refunds are processed within 5 business days.", "contexts": [result.content]}
            return {"text": "Refunds are processed within 5 business days."}
        if "budget" in question:
            raise BudgetExceededError("cap")
        return {"text": "The capital of France is Paris."}


def make_runner(tmp_path: Path, backends: list[str], *, tasks: list[dict], questions: list[dict]) -> Any:
    tasks_file = tmp_path / "tasks.yaml"
    tasks_file.write_text(yaml.safe_dump({"tasks": tasks}))
    rag_file = tmp_path / "rag.yaml"
    rag_file.write_text(yaml.safe_dump({"questions": questions}))
    quality = QualitySuiteConfig(tasks=str(tasks_file), rag=str(rag_file), backends=backends, trials_per_task=2)
    config = types.SimpleNamespace(
        suites=types.SimpleNamespace(quality=quality),
        run=types.SimpleNamespace(trials_per_case=5, seed=1, concurrency=4),
    )
    return types.SimpleNamespace(
        config=config,
        options=types.SimpleNamespace(trials=None),
        run_id="run-q",
        offline=True,
        _path=Path,
    )


TASKS = [
    {
        "id": "QT-001",
        "goal": "What is the status of order O-2002?",
        "expected_trajectory": [{"tool": "db_query", "args": {"table": "^orders$", "where": "O-2002"}}],
        "success": {"type": "output_contains", "value": "processing"},
    },
    {
        "id": "QT-002",
        "goal": "What is the capital of France?",
        "success": {"type": "judge"},
        "reference": "The capital of France is Paris.",
    },
    {
        "id": "QT-003",
        "goal": "Which tool did you call for O-2002?",
        "expected_trajectory": [{"tool": "db_query"}],
        "success": {"type": "tool_called", "tool": "db_query", "args": {"table": "orders"}},
    },
]
QUESTIONS = [
    {
        "id": "RQ-001",
        "question": "How long does a refund take?",
        "reference_answer": "Refunds are processed within 5 business days.",
        "relevant_docs": ["refund-policy"],
    },
    {
        "id": "RQ-002",
        "question": "Refund timing with contexts please?",
        "reference_answer": "Refunds are processed within 5 business days.",
        "relevant_docs": ["refund-policy"],
    },
]


def driver() -> ConversationDriver:
    return ConversationDriver(
        PythonCallableTarget("quality", obj=QualityAgent()),
        Policy(),
        rag_corpus=RagCorpus.load("datasets/rag_corpus"),
        max_retries=0,
    )


class TestQualitySuite:
    def test_carrier_case(self) -> None:
        case = carrier_case("QT-001", "do it")
        assert case.turns[0].content == "do it"
        assert case.detectors == ["refusal"]
        assert not case.mutations_allowed

    def test_run(self, tmp_path: Path) -> None:
        runner = make_runner(tmp_path, ["builtin", "ragas", "deepeval"], tasks=TASKS, questions=QUESTIONS)
        report = asyncio.run(run_quality_suite(runner, driver(), Policy(), MockJudge()))
        assert report.n_tasks == 3
        per_task = {row["id"]: row for row in report.per_task}
        assert per_task["QT-001"]["success_rate"] == 1.0
        assert per_task["QT-002"]["success_rate"] == 1.0  # judged by MockJudge against the reference
        assert per_task["QT-003"]["success_rate"] == 1.0
        assert per_task["QT-001"]["consistency_exact"] == 1.0
        assert report.task_success_rate == 1.0
        assert report.trajectory["recall"] == 1.0
        assert report.trajectory["exact_match"] == 1.0
        assert set(report.rag) == {"faithfulness", "answer_relevancy", "context_precision", "context_recall"}
        assert report.rag["context_precision"] == 1.0
        assert {q["id"] for q in report.per_question} == {"RQ-001", "RQ-002"}
        assert report.consistency == {"exact_match": 1.0, "token_jaccard": 1.0}
        assert report.backends["builtin"]["task_success_rate"] == 1.0
        assert len(report.backend_messages) == 2
        assert all("skipped" in m for m in report.backend_messages)
        assert report.performance.n_calls == 2 * (3 + 2)

    def test_backend_scores_recorded(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        install_ragas(monkeypatch, {"faithfulness": 0.9})
        runner = make_runner(tmp_path, ["ragas"], tasks=[], questions=QUESTIONS[:1])
        runner.offline = False
        report = asyncio.run(run_quality_suite(runner, driver(), Policy(), MockJudge()))
        assert report.backends["ragas"] == {"faithfulness": 0.9}
        assert report.task_success_rate is None
        assert "task_success_rate" not in report.backends["builtin"]

    def test_budget_abort_raises(self, tmp_path: Path) -> None:
        tasks = [{"id": "QT-009", "goal": "blow the budget", "success": {"type": "judge"}}]
        runner = make_runner(tmp_path, ["builtin"], tasks=tasks, questions=[])
        with pytest.raises(BudgetExceededError):
            asyncio.run(run_quality_suite(runner, driver(), Policy(), MockJudge()))

    def test_no_datasets(self, tmp_path: Path) -> None:
        runner = make_runner(tmp_path, ["builtin"], tasks=[], questions=[])
        runner.config.suites.quality = QualitySuiteConfig(backends=["builtin"])
        report = asyncio.run(run_quality_suite(runner, driver(), Policy(), MockJudge()))
        assert report.n_tasks == 0
        assert report.task_success_rate is None
        assert report.consistency == {}
