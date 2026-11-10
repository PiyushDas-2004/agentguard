"""Invalid judge JSON and budget exhaustion are handled without crashing the run."""

from __future__ import annotations

import pytest

import agentguard.core.runner as runner_module
from agentguard.cli import exit_code_for
from agentguard.core.errors import ExitCode
from agentguard.core.runner import RunOptions
from agentguard.judges.base import JudgeRequest
from agentguard.judges.llm_judge import LLMJudge
from agentguard.llm.mock import MockLLM
from agentguard.reporting.markdown import render_markdown
from agentguard.storage.db import Database
from agentguard.targets.base import TargetResponse
from tests.failure_injection._support import case, make_config, make_runner, run

VALID = '{"violated": false, "score": 0.1, "rationale": "The reply is harmless."}'


async def test_llm_judge_repairs_then_gives_up_as_inconclusive():
    llm = MockLLM("scripted", script=["not json at all", '{"violated": "maybe"}', "```json\n{broken```"])
    judge = LLMJudge(llm, max_repair_retries=2)
    result = await judge.judge(JudgeRequest(rubric="jailbreak", user_input="hi", response="hello"))
    assert result.violated is None
    assert result.inconclusive is True
    assert result.attempts == 3
    assert llm.calls == 3
    assert "not json at all" in result.raw


async def test_llm_judge_repair_succeeds_on_second_attempt():
    llm = MockLLM("scripted", script=["Sure, here you go: {oops", VALID])
    result = await LLMJudge(llm, max_repair_retries=2).judge(
        JudgeRequest(rubric="jailbreak", user_input="hi", response="hello")
    )
    assert result.violated is False
    assert result.attempts == 2


def test_invalid_judge_json_marks_trial_inconclusive_and_excludes_it_from_n(tmp_path, monkeypatch):
    # Trial 0: invalid then valid (repaired). Trial 1: invalid three times -> inconclusive.
    # Trial 2: valid immediately. Concurrency 1 keeps the script order deterministic.
    script = ["garbage", VALID, "nope", "still nope", "{not: json}", VALID]
    llm = MockLLM("scripted", script=script)
    monkeypatch.setattr(
        runner_module, "build_judge", lambda config, offline, budget=None: LLMJudge(llm, max_repair_retries=2)
    )
    config = make_config(
        tmp_path,
        [case("FI-JDG-001", category="JAILBREAK", detectors=["judge"])],
        run={"trials_per_case": 3, "max_error_fraction": 0.5},
    )
    result = run(make_runner(config, lambda message: "Here is a friendly, harmless answer."))

    assert not result.partial
    (case_result,) = result.cases
    assert case_result.n_inconclusive == 1
    assert case_result.n_trials == 2  # inconclusive trial excluded from n
    assert case_result.n_errors == 0
    assert case_result.n_violations == 0
    assert llm.calls == 6
    calls = Database(tmp_path / "agentguard.db").judge_calls(result.run_id)
    assert sorted(c.attempts for c in calls) == [1, 2, 3]
    assert sum(1 for c in calls if c.violated is None) == 1


def test_inconclusive_judge_counts_toward_error_fraction(tmp_path, monkeypatch):
    llm = MockLLM("scripted", script=["x"] * 9)
    monkeypatch.setattr(
        runner_module, "build_judge", lambda config, offline, budget=None: LLMJudge(llm, max_repair_retries=2)
    )
    config = make_config(
        tmp_path, [case("FI-JDG-002", category="JAILBREAK", detectors=["judge"])], run={"trials_per_case": 3}
    )
    result = run(make_runner(config, lambda message: "ok"))
    assert result.cases[0].n_inconclusive == 3
    assert result.cases[0].n_trials == 0
    assert result.cases[0].status.value == "inconclusive"


def test_budget_exceeded_mid_run_returns_partial_result(tmp_path):
    async def expensive_agent(conversation, tools, context):
        return TargetResponse(text="answer", cost_usd=0.01)

    cases = [case(f"FI-BUD-{i:03d}") for i in range(1, 11)]
    config = make_config(tmp_path, cases, run={"max_cost_usd": 0.035, "trials_per_case": 1})
    runner = make_runner(config, expensive_agent)
    result = run(runner)

    assert result.partial is True
    assert result.abort_reason == "budget"
    assert exit_code_for(result) == ExitCode.BUDGET_EXCEEDED == 4
    assert 1 <= result.total_trials < 10
    assert result.total_cost_usd > 0.035
    assert any("budget exceeded" in w for w in result.warnings)
    assert "Partial" in render_markdown(result) or "PARTIAL" in render_markdown(result)
    # Partial results are persisted.
    stored = Database(tmp_path / "agentguard.db").load_run(result.run_id)
    assert stored.partial
    assert stored.abort_reason == "budget"
    assert stored.total_trials == result.total_trials


def test_budget_override_from_options(tmp_path):
    async def expensive_agent(conversation, tools, context):
        return TargetResponse(text="answer", cost_usd=0.5)

    config = make_config(tmp_path, [case("FI-BUD-001"), case("FI-BUD-002")], run={"max_cost_usd": 100})
    result = run(make_runner(config, expensive_agent, options=RunOptions(offline=True, max_cost_usd=0.4)))
    assert result.abort_reason == "budget"
    assert result.total_trials == 0
    assert result.cases == []


def test_budget_exceeded_via_metered_target_llm(tmp_path):
    async def llm_agent(conversation, tools, context):
        response = await context.llm.complete(conversation)
        return response.text or "done"

    cases = [case(f"FI-BUD-{i:03d}") for i in range(1, 6)]
    config = make_config(tmp_path, cases, run={"max_cost_usd": 0.0000001, "trials_per_case": 2})
    result = run(make_runner(config, llm_agent))
    assert result.partial
    assert result.abort_reason == "budget"
    assert exit_code_for(result) == ExitCode.BUDGET_EXCEEDED


@pytest.mark.parametrize("abort", [None, "interrupted"])
def test_exit_codes_for_non_budget_results(tmp_path, abort):
    config = make_config(tmp_path, [case("FI-EXT-001")], run={"fail_threshold_risk": 100})
    result = run(make_runner(config, lambda message: "nothing to see"))
    result = result.model_copy(update={"partial": abort is not None, "abort_reason": abort})
    expected = ExitCode.RUNTIME_ERROR if abort else ExitCode.OK
    assert exit_code_for(result) == expected
