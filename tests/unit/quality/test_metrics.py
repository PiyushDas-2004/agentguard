"""Hand-computed quality metrics: trajectory, task success, consistency, RAG, performance, datasets."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from agentguard.core.errors import DatasetError
from agentguard.core.types import ErrorInfo, Role, ToolCall, Transcript, TranscriptTurn, Trial
from agentguard.quality.consistency import consistency, normalize_answer, token_jaccard
from agentguard.quality.datasets import ExpectedCall, QualityTask, load_rag_questions, load_tasks
from agentguard.quality.performance import performance_report
from agentguard.quality.rag_metrics import (
    answer_relevancy,
    context_precision,
    context_recall,
    faithfulness,
    retrieved_doc_ids,
)
from agentguard.quality.task_success import check_success
from agentguard.quality.trajectory import call_matches, score_trajectory


def call(name: str, **args: object) -> ToolCall:
    return ToolCall(name=name, arguments=dict(args))


def exp(tool: str, **args: str) -> ExpectedCall:
    return ExpectedCall(tool=tool, args=dict(args))


class TestTrajectory:
    def test_call_matches(self) -> None:
        assert call_matches(exp("db_query", table="^orders$"), call("db_query", table="ORDERS"))
        assert not call_matches(exp("db_query", table="^orders$"), call("db_query", table="customers"))
        assert not call_matches(exp("db_query"), call("file_read"))
        assert call_matches(exp("db_query", where="O-2002"), call("db_query", where={"id": "O-2002"}))
        assert not call_matches(exp("db_query", where="x"), call("db_query"))

    def test_exact(self) -> None:
        s = score_trajectory([exp("a"), exp("b")], [call("a"), call("b")])
        assert (s.exact_match, s.in_order_match, s.any_order_match) == (True, True, True)
        assert (s.precision, s.recall, s.f1, s.argument_correctness, s.unnecessary_calls) == (1, 1, 1, 1, 0)

    def test_reordered(self) -> None:
        s = score_trajectory([exp("a"), exp("b")], [call("b"), call("a")])
        assert (s.exact_match, s.in_order_match, s.any_order_match) == (False, False, True)
        assert s.f1 == 1.0

    def test_extra_calls(self) -> None:
        # expected a,b; actual a,x,b,b: in order, precision 2/4, recall 1, f1 = 2*.5*1/1.5
        s = score_trajectory([exp("a"), exp("b")], [call("a"), call("x"), call("b"), call("b")])
        assert not s.exact_match and s.in_order_match and s.any_order_match
        assert s.precision == 0.5 and s.recall == 1.0
        assert s.f1 == round(2 * 0.5 / 1.5, 4)
        # unnecessary: one unexpected tool (x) + (3 relevant - 2 expected)
        assert s.unnecessary_calls == 2
        assert s.argument_correctness == 1.0

    def test_wrong_arguments(self) -> None:
        s = score_trajectory([exp("db", t="^orders$")], [call("db", t="employees"), call("db", t="orders")])
        assert not s.exact_match and s.in_order_match
        assert s.precision == 0.5 and s.recall == 1.0
        assert s.argument_correctness == 0.5

    def test_missing_call(self) -> None:
        s = score_trajectory([exp("a"), exp("b")], [call("a")])
        assert not s.in_order_match and not s.any_order_match
        assert s.precision == 1.0 and s.recall == 0.5 and s.f1 == round(2 * 0.5 / 1.5, 4)

    def test_empty_cases(self) -> None:
        none = score_trajectory([], [])
        assert none.exact_match and none.precision == 1.0 and none.recall == 1.0 and none.argument_correctness == 1.0
        nothing_done = score_trajectory([exp("a")], [])
        assert nothing_done.precision == 0.0 and nothing_done.recall == 0.0 and nothing_done.f1 == 0.0
        assert nothing_done.argument_correctness == 0.0
        unexpected = score_trajectory([], [call("x")])
        assert unexpected.precision == 0.0 and unexpected.recall == 1.0 and unexpected.unnecessary_calls == 1

    def test_approval_requests_ignored(self) -> None:
        approval = ToolCall(name="a", is_approval_request=True)
        s = score_trajectory([exp("a")], [approval, call("a")])
        assert s.exact_match


def task(success: dict, **kwargs: object) -> QualityTask:
    return QualityTask.model_validate({"id": "QT-1", "goal": "g", "success": success, **kwargs})


class TestTaskSuccess:
    def test_output_contains(self) -> None:
        t = task({"type": "output_contains", "value": "Shipped"})
        assert check_success(t, "It has SHIPPED.", []) is True
        assert check_success(t, "pending", []) is False

    def test_output_regex(self) -> None:
        t = task({"type": "output_regex", "value": r"\b379(\.0+)?\b"})
        assert check_success(t, "Total: 379.00", []) is True
        assert check_success(t, "Total: 3790", []) is False

    def test_tool_called_with_args(self) -> None:
        t = task({"type": "tool_called", "tool": "email_send", "args": {"to": "@acme\\.example$"}})
        assert check_success(t, "", [call("email_send", to="bob@acme.example")]) is True
        assert check_success(t, "", [call("email_send", to="bob@evil.example")]) is False
        not_executed = ToolCall(name="email_send", arguments={"to": "bob@acme.example"}, executed=False)
        assert check_success(t, "", [not_executed]) is False
        approval = ToolCall(name="email_send", arguments={"to": "bob@acme.example"}, is_approval_request=True)
        assert check_success(t, "", [approval]) is False

    def test_tool_called_value_fallback(self) -> None:
        t = task({"type": "tool_called", "value": "search_docs"})
        assert check_success(t, "", [call("search_docs", query="x")]) is True
        assert check_success(t, "", [call("file_read")]) is False

    def test_judge_returns_none(self) -> None:
        assert check_success(task({"type": "judge"}), "anything", []) is None


class TestConsistency:
    def test_normalize(self) -> None:
        assert normalize_answer("  Hello,   WORLD!! ") == "hello world"

    def test_jaccard(self) -> None:
        assert token_jaccard("a b c", "b c d") == 0.5
        assert token_jaccard("", "!!") == 1.0
        assert token_jaccard("a", "") == 0.0

    def test_consistency(self) -> None:
        assert consistency([]) == (1.0, 1.0)
        assert consistency(["x"]) == (1.0, 1.0)
        # pairs: (A,A') exact, (A,B) not, (A',B) not → exact 1/3; jaccard (1 + 2/5 + 2/5)/3
        exact, jac = consistency(["a b c", "A, b c!", "b c d e"])
        assert exact == round(1 / 3, 4)
        assert jac == round((1 + 0.4 + 0.4) / 3, 4)


class TestRagMetrics:
    CONTEXTS = [
        "[doc:refund-policy] Refunds\nRefunds are processed within five business days.",
        "[doc:shipping-policy] Shipping\nStandard shipping takes three days. [doc:refund-policy]",
    ]

    def test_retrieved_doc_ids(self) -> None:
        assert retrieved_doc_ids(self.CONTEXTS) == ["refund-policy", "shipping-policy"]
        assert retrieved_doc_ids(["no markers"]) == []

    def test_faithfulness(self) -> None:
        assert faithfulness("Refunds are processed within five business days.", self.CONTEXTS) == 1.0
        assert faithfulness("Refunds processed within five business days. Unicorns deliver parcels.", self.CONTEXTS) == 0.5
        assert faithfulness("Ok.", self.CONTEXTS) == 1.0

    def test_answer_relevancy(self) -> None:
        assert answer_relevancy("Refunds take five days", "How long do refunds take?") == round(2 / 3, 4)
        assert answer_relevancy("anything", "what is it?") == 1.0

    def test_context_precision_hand_computed(self) -> None:
        # ranks: rel, irr, rel → AP = (1/1 + 2/3) / min(2, 3)
        assert context_precision(["a", "x", "b"], ["a", "b"]) == round((1 + 2 / 3) / 2, 4)
        assert context_precision(["x", "a"], ["a"]) == 0.5
        assert context_precision(["x"], ["a"]) == 0.0
        assert context_precision([], ["a"]) == 0.0
        assert context_precision(["a"], []) == 0.0
        assert context_precision(["a"], ["a", "b", "c"]) == 1.0

    def test_context_recall(self) -> None:
        assert context_recall("Refunds are processed within five business days.", self.CONTEXTS) == 1.0
        assert context_recall("Gift cards never expire anywhere.", self.CONTEXTS) == 0.0
        assert context_recall("", self.CONTEXTS) == 1.0


def trial(latencies: list[float], *, error: bool = False, cost: float = 0.0, tokens: tuple[int, int] = (0, 0)) -> Trial:
    turns = [TranscriptTurn(index=0, role=Role.user, content="q", tokens_in=tokens[0])]
    for i, lat in enumerate(latencies, 1):
        turns.append(
            TranscriptTurn(index=i, role=Role.assistant, content="a", latency_ms=lat, cost_usd=cost, tokens_out=tokens[1])
        )
    return Trial(
        run_id="r",
        case_id="QT-001",
        trial_index=0,
        seed=0,
        transcript=Transcript(turns=turns),
        error=ErrorInfo(type="X", message="m") if error else None,
    )


class TestPerformance:
    def test_empty(self) -> None:
        report = performance_report([])
        assert report.n_calls == 0 and report.cost_per_task_usd == 0.0 and report.error_rate == 0.0

    def test_values(self) -> None:
        trials = [
            trial([100.0, 200.0], cost=0.01, tokens=(10, 5)),
            trial([300.0], error=True, cost=0.02, tokens=(4, 1)),
            trial([400.0]),
        ]
        report = performance_report(trials)
        assert report.n_calls == 4
        assert report.latency_p50_ms == pytest.approx(250.0)
        assert report.latency_p99_ms <= 400.0 and report.latency_p95_ms >= report.latency_p50_ms
        assert report.tokens_in == 14 and report.tokens_out == 11
        assert report.cost_usd == pytest.approx(0.04)
        assert report.cost_per_task_usd == pytest.approx(0.04 / 3)
        assert report.error_rate == round(1 / 3, 4)


class TestDatasets:
    def test_real_files(self) -> None:
        tasks = load_tasks("datasets/quality/tasks.yaml")
        assert len(tasks) >= 30 and tasks[0].id == "QT-001"
        questions = load_rag_questions("datasets/quality/rag_qa.yaml")
        assert len(questions) >= 20 and questions[0].relevant_docs

    def test_missing(self, tmp_path: Path) -> None:
        with pytest.raises(DatasetError, match="dataset not found"):
            load_tasks(tmp_path / "nope.yaml")

    def test_invalid_yaml(self, tmp_path: Path) -> None:
        f = tmp_path / "t.yaml"
        f.write_text("tasks: [oops\n")
        with pytest.raises(DatasetError, match="invalid YAML"):
            load_tasks(f)

    def test_schema_error_path(self, tmp_path: Path) -> None:
        f = tmp_path / "t.yaml"
        f.write_text(yaml.safe_dump({"tasks": [{"id": "Q", "goal": "g", "success": {"type": "vibes"}}]}))
        with pytest.raises(DatasetError, match=r"tasks\[0\]\.success\.type"):
            load_tasks(f)

    def test_duplicate_task_ids(self, tmp_path: Path) -> None:
        item = {"id": "Q", "goal": "g", "success": {"type": "judge"}}
        f = tmp_path / "t.yaml"
        f.write_text(yaml.safe_dump({"tasks": [item, item]}))
        with pytest.raises(DatasetError, match="duplicate task ids"):
            load_tasks(f)

    def test_rag_requires_relevant_docs(self, tmp_path: Path) -> None:
        f = tmp_path / "r.yaml"
        f.write_text(
            yaml.safe_dump({"questions": [{"id": "R", "question": "q", "reference_answer": "a", "relevant_docs": []}]})
        )
        with pytest.raises(DatasetError, match=r"questions\[0\]\.relevant_docs"):
            load_rag_questions(f)
