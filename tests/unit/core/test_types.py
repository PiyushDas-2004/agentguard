"""Validators and helpers of agentguard.core.types and core.errors."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from agentguard.core.errors import (
    AgentGuardError,
    BudgetExceededError,
    ConfigError,
    ExitCode,
    TargetError,
    TargetTimeoutError,
    error_info_from_exception,
)
from agentguard.core.types import (
    SEVERITY_WEIGHTS,
    AttackCase,
    AttackCategory,
    CaseResult,
    CaseStatus,
    EvidenceSpan,
    InjectionVector,
    Objective,
    Poison,
    Role,
    RunResult,
    Severity,
    TargetInfo,
    Transcript,
    TranscriptTurn,
    Trial,
    utcnow,
)


def _case(**overrides: object) -> dict:
    data: dict = {
        "id": "PI-IND-017",
        "category": "PI_DIRECT",
        "title": "Title",
        "description": "A long enough description",
        "severity": "high",
        "vector": "user_message",
        "turns": [{"content": "hi"}],
        "objective": {"type": "canary_leak", "description": "leak"},
        "detectors": ["canary"],
    }
    data.update(overrides)
    return data


class TestSeverity:
    def test_weights(self) -> None:
        assert [s.weight for s in Severity] == [10, 7, 4, 1, 0]
        assert SEVERITY_WEIGHTS[Severity.high] == 7

    def test_string_values(self) -> None:
        assert Severity("critical") == "critical"
        assert CaseStatus.passed.value == "pass"


class TestAttackCaseValidators:
    def test_valid(self) -> None:
        case = AttackCase.model_validate(_case())
        assert case.sessions == [1]

    @pytest.mark.parametrize("cid", ["PI-IND-017", "A-001", "DOW-1-002", "X9-123"])
    def test_ids_ok(self, cid: str) -> None:
        assert AttackCase.model_validate(_case(id=cid)).id == cid

    @pytest.mark.parametrize("cid", ["pi-ind-017", "PI-IND-17", "PI_IND-017", "1A-001", "PI--001", "PI-IND-0170", ""])
    def test_ids_bad(self, cid: str) -> None:
        with pytest.raises(ValidationError, match="must look like 'PI-IND-017'"):
            AttackCase.model_validate(_case(id=cid))

    def test_sessions_sorted_distinct(self) -> None:
        turns = [{"content": "a", "session": 2}, {"content": "b", "session": 1}, {"content": "c", "session": 2}]
        assert AttackCase.model_validate(_case(turns=turns)).sessions == [1, 2]

    def test_non_user_vector_requires_poison(self) -> None:
        with pytest.raises(ValidationError, match="requires a 'poison' block"):
            AttackCase.model_validate(_case(vector="rag_document"))

    def test_poison_vector_must_match(self) -> None:
        with pytest.raises(ValidationError, match="poison.vector must equal the case vector"):
            AttackCase.model_validate(_case(vector="rag_document", poison={"vector": "email_body", "content": "x"}))

    def test_poison_ok(self) -> None:
        case = AttackCase.model_validate(_case(vector="rag_document", poison={"vector": "rag_document", "content": "x"}))
        assert case.poison is not None and case.poison.vector == InjectionVector.rag_document

    def test_extra_key_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            AttackCase.model_validate(_case(severty="high"))

    def test_turn_and_detector_minimums(self) -> None:
        with pytest.raises(ValidationError):
            AttackCase.model_validate(_case(turns=[]))
        with pytest.raises(ValidationError):
            AttackCase.model_validate(_case(detectors=[]))
        with pytest.raises(ValidationError):
            AttackCase.model_validate(_case(title="ab"))


class TestPoison:
    def test_needs_content_or_doc(self) -> None:
        with pytest.raises(ValidationError, match="either 'content' or 'corpus_doc'"):
            Poison(vector=InjectionVector.memory)
        assert Poison(vector=InjectionVector.memory, corpus_doc="d").corpus_doc == "d"

    def test_user_message_rejected(self) -> None:
        with pytest.raises(ValidationError, match="cannot be user_message"):
            Poison(vector=InjectionVector.user_message, content="x")


class TestObjective:
    def test_tool_call_requires_tool(self) -> None:
        with pytest.raises(ValidationError, match="require 'tool'"):
            Objective(type="tool_call", description="d")

    def test_output_regex_requires_pattern(self) -> None:
        with pytest.raises(ValidationError, match="require 'pattern'"):
            Objective(type="output_regex", description="d")

    def test_invalid_regexes(self) -> None:
        with pytest.raises(ValidationError, match="invalid regex"):
            Objective(type="output_regex", description="d", pattern="(")
        with pytest.raises(ValidationError, match="invalid regex"):
            Objective(type="tool_call", description="d", tool="t", args_match={"a": "["})

    def test_valid(self) -> None:
        o = Objective(type="tool_call", description="d", tool="t", args_match={"a": "^x"})
        assert o.tool == "t"


class TestEvidenceSpan:
    def test_ordering(self) -> None:
        with pytest.raises(ValidationError, match="end must be >= start"):
            EvidenceSpan(turn_index=0, start=5, end=4, text="", reason="")
        assert EvidenceSpan(turn_index=-1, start=3, end=3, text="", reason="r").end == 3

    def test_negative_start(self) -> None:
        with pytest.raises(ValidationError):
            EvidenceSpan(turn_index=0, start=-1, end=0, text="", reason="")


class TestTranscript:
    def test_aggregates(self) -> None:
        t = Transcript(
            turns=[
                TranscriptTurn(index=0, role=Role.user, content="u1", tokens_in=1, cost_usd=0.5, latency_ms=2),
                TranscriptTurn(index=1, role=Role.assistant, content="a1", tokens_out=3, cost_usd=0.25),
                TranscriptTurn(index=2, role=Role.tool, content="t"),
                TranscriptTurn(index=3, role=Role.assistant, content="a2", tokens_in=4, latency_ms=3),
            ]
        )
        assert t.tokens_in == 5
        assert t.tokens_out == 3
        assert t.cost_usd == 0.75
        assert t.latency_ms == 5
        assert t.assistant_text() == "a1\na2"
        assert t.user_text() == "u1"


class TestTrialAndRun:
    def test_trial_id(self) -> None:
        t = Trial(run_id="r", case_id="C-001", trial_index=2, seed=1)
        assert t.trial_id == "r:C-001:seed:2"
        assert Trial(run_id="r", case_id="C-001", trial_index=0, seed=1, mutation_id="m").trial_id == "r:C-001:m:0"

    def test_utcnow_aware(self) -> None:
        assert utcnow().tzinfo is not None

    def test_run_result_helpers(self) -> None:
        def cr(cat: AttackCategory) -> CaseResult:
            return CaseResult(
                case_id="X-001",
                category=cat,
                n_trials=1,
                n_errors=0,
                n_violations=0,
                violation_rate=0,
                ci_low=0,
                ci_high=0,
                severity=Severity.low,
                risk_contribution=0,
                status=CaseStatus.passed,
            )

        rr = RunResult(
            run_id="r",
            name="n",
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            target=TargetInfo(type="t", name="n"),
            config_hash="h",
            agentguard_version="0",
            seed=1,
            trials_per_case=1,
            fail_threshold_risk=40,
            risk_score=40,
            cases=[cr(AttackCategory.PI_DIRECT), cr(AttackCategory.OVER_REFUSAL)],
        )
        assert rr.passed_threshold
        assert [c.category for c in rr.security_cases()] == [AttackCategory.PI_DIRECT]
        assert not rr.model_copy(update={"risk_score": 40.01}).passed_threshold


class TestErrors:
    def test_exit_codes(self) -> None:
        assert int(ExitCode.CONFIG_ERROR) == 2
        assert int(ExitCode.BUDGET_EXCEEDED) == 4

    def test_retryable_overrides(self) -> None:
        assert not AgentGuardError("x").retryable
        assert AgentGuardError("x", retryable=True).retryable
        assert TargetTimeoutError("t").retryable
        assert not TargetTimeoutError("t", retryable=False).retryable
        err = TargetError("boom", status_code=503, retryable=True)
        assert err.status_code == 503 and err.message == "boom"

    @pytest.mark.parametrize(
        ("exc", "retryable"),
        [
            (ConfigError("bad"), False),
            (TargetError("x", retryable=True), True),
            (TargetTimeoutError("slow"), True),
            (BudgetExceededError("cap"), False),
            (TimeoutError("t"), True),
            (asyncio.TimeoutError(), True),
            (ConnectionResetError("r"), True),
            (ValueError("v"), False),
        ],
    )
    def test_error_info_from_exception(self, exc: BaseException, retryable: bool) -> None:
        info = error_info_from_exception(exc)
        assert info.type == type(exc).__name__
        assert info.retryable is retryable

    def test_empty_message_uses_class_name_and_truncates(self) -> None:
        assert error_info_from_exception(KeyError()).message == "KeyError"
        assert len(error_info_from_exception(RuntimeError("x" * 5000)).message) == 2000
