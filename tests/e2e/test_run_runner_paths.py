"""Runner configuration paths: judge construction, category config, inline policy, helpers."""

from __future__ import annotations

import subprocess

import agentguard.core.runner as runner_module
import agentguard.quality.suite as quality_suite
from agentguard.config.models import JudgeConfig
from agentguard.core.errors import BudgetExceededError
from agentguard.core.runner import RunOptions, Runner, build_judge, git_sha, new_run_id, run_sync
from agentguard.core.types import AttackCategory
from agentguard.judges.ensemble import EnsembleJudge
from agentguard.judges.llm_judge import LLMJudge
from agentguard.judges.mock_judge import MockJudge
from agentguard.targets.base import MeteredLLM
from tests.failure_injection._support import ROOT, case, demo_config, make_config, make_runner, run


def test_build_judge_variants(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-not-used")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-used")
    assert isinstance(build_judge(JudgeConfig(provider="anthropic", model="m"), offline=True), MockJudge)
    live = build_judge(JudgeConfig(provider="openai", model="gpt-test", max_repair_retries=4), offline=False)
    assert isinstance(live, LLMJudge)
    assert isinstance(live.llm, MeteredLLM)
    assert live.max_repair_retries == 4
    ensemble = build_judge(JudgeConfig(provider="mock", ensemble=True), offline=False)
    assert isinstance(ensemble, EnsembleJudge)
    mixed = build_judge(
        JudgeConfig(provider="mock", ensemble=True, second_provider="anthropic", second_model="x"), offline=False
    )
    assert isinstance(mixed, EnsembleJudge)


def test_git_sha_and_run_id(monkeypatch):
    sha = git_sha()
    assert sha is None or len(sha) == 40
    run_id = new_run_id()
    assert len(run_id) == len("20261109-153012-a1b2c3")
    assert new_run_id() != run_id

    def no_git(*args, **kwargs):
        raise OSError("git not installed")

    monkeypatch.setattr(subprocess, "run", no_git)
    assert git_sha() is None


def test_categories_from_config_and_inline_policy(tmp_path):
    cases = [case("FI-CAT-001"), case("FI-CAT-002", category="JAILBREAK")]
    base = make_config(tmp_path, cases, security={"categories": ["JAILBREAK"]})
    import yaml

    policy = yaml.safe_load((ROOT / "examples" / "policy.yaml").read_text(encoding="utf-8"))
    config = base.model_copy(update={"policy": policy})
    runner = Runner(config, RunOptions(offline=True), base_dir=ROOT)
    assert [c.id for c in runner.load_cases()] == ["FI-CAT-002"]
    assert runner.load_policy().limits.max_output_chars == 20000
    assert runner.offline is True


def test_security_suite_disabled_with_quality(tmp_path):
    config = demo_config(tmp_path, ["PI-DIR-001"], trials=1, quality=True)
    config = config.model_copy(
        update={
            "suites": config.suites.model_copy(
                update={"security": config.suites.security.model_copy(update={"enabled": False})}
            )
        }
    )
    result = run_sync(Runner(config, RunOptions(offline=True), base_dir=ROOT))
    assert result.cases == [] and result.quality is not None


def test_budget_exhausted_during_quality_suite_is_partial(tmp_path, monkeypatch):
    async def exhausted(*args, **kwargs):
        raise BudgetExceededError("budget exceeded: quality")

    monkeypatch.setattr(quality_suite, "run_quality_suite", exhausted)
    config = demo_config(tmp_path, ["PI-DIR-001"], trials=1, mutations=False, quality=True)
    result = run(Runner(config, RunOptions(offline=True), base_dir=ROOT))
    assert result.partial and result.abort_reason == "budget"
    assert result.total_trials == 1
    assert "budget exceeded" in result.warnings


def test_rate_limited_concurrent_run(tmp_path):
    cases = [case(f"FI-RTL-{i:03d}") for i in range(1, 9)]
    config = make_config(tmp_path, cases, run={"concurrency": 4, "rate_limit_per_second": 200})
    result = run(make_runner(config, lambda message: "fine"))
    assert result.total_trials == 8 and result.total_errors == 0


def test_flush_in_batches_of_fifty(tmp_path):
    cases = [case(f"FI-BAT-{i:03d}") for i in range(1, 27)]
    config = make_config(tmp_path, cases, run={"trials_per_case": 2, "concurrency": 8})
    runner = make_runner(config, lambda message: "fine")
    result = run(runner)
    assert result.total_trials == 52
    assert len(runner.database.trial_rows(result.run_id)) == 52


def test_runner_module_exports():
    assert set(runner_module.__all__) >= {"RunOptions", "Runner", "TrialSpec", "build_judge"}
    assert AttackCategory.PI_DIRECT in {AttackCategory(c) for c in ["PI_DIRECT"]}
