"""Target failures (timeout, exception, malformed response, HTTP 429/5xx) never crash a run."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from agentguard.core.errors import TargetError
from agentguard.core.types import CaseStatus
from agentguard.storage.db import Database
from tests.failure_injection._support import case, make_config, make_runner, run

CASES = [case("FI-TST-001"), case("FI-TST-002")]


def test_target_timeout_is_recorded_as_error_and_run_completes(tmp_path):
    async def slow_agent(conversation, tools, context):
        if context.case_id == "FI-TST-001":
            await asyncio.sleep(5)
        return "fine"

    config = make_config(tmp_path, CASES, run={"timeout_seconds": 0.2, "trials_per_case": 2})
    result = run(make_runner(config, slow_agent))

    assert not result.partial
    assert result.total_trials == 4
    assert result.total_errors == 2
    by_id = {c.case_id: c for c in result.cases}
    slow = by_id["FI-TST-001"]
    assert slow.n_errors == 2
    assert slow.n_trials == 0
    assert slow.status == CaseStatus.inconclusive
    error = slow.samples[0].error
    assert error is not None
    assert error.type == "TargetTimeoutError"
    assert error.retryable is True
    assert "did not respond within 0.2s" in error.message
    assert by_id["FI-TST-002"].n_errors == 0
    assert by_id["FI-TST-002"].n_trials == 2
    assert by_id["FI-TST-002"].n_violations == 0
    assert result.performance.error_rate == pytest.approx(0.5)


def test_target_exception_is_captured_per_trial(tmp_path):
    async def broken_agent(conversation, tools, context):
        if context.case_id == "FI-TST-001":
            raise ValueError("agent blew up")
        return "fine"

    config = make_config(tmp_path, CASES)
    runner = make_runner(config, broken_agent)
    result = run(runner)

    assert not result.partial
    assert result.total_errors == 1
    failing = next(c for c in result.cases if c.case_id == "FI-TST-001")
    assert failing.samples[0].error is not None
    assert failing.samples[0].error.type == "ValueError"
    assert failing.samples[0].error.message == "agent blew up"
    assert failing.samples[0].error.retryable is False
    # Persisted with the error, and the run itself is stored as completed.
    rows = Database(tmp_path / "agentguard.db").trial_rows(result.run_id, "FI-TST-001")
    assert [r.error_type for r in rows] == ["ValueError"]
    assert Database(tmp_path / "agentguard.db").load_run(result.run_id).total_errors == 1


def test_sync_agent_exception_is_captured(tmp_path):
    def sync_agent(message: str) -> str:
        raise RuntimeError("sync failure")

    result = run(make_runner(make_config(tmp_path, CASES[:1]), sync_agent))
    assert result.total_errors == 1
    assert result.cases[0].samples[0].error.type == "RuntimeError"


@pytest.mark.parametrize("bad", [42, None, ["list"], {"no_text_key": 1}])
def test_malformed_response_is_a_non_retryable_target_error(tmp_path, bad):
    calls = 0

    async def malformed_agent(conversation, tools, context):
        nonlocal calls
        calls += 1
        return bad

    config = make_config(tmp_path, CASES[:1], run={"max_retries": 3})
    result = run(make_runner(config, malformed_agent))
    error = result.cases[0].samples[0].error
    assert error is not None
    assert error.type == "TargetError"
    assert "malformed target response of type" in error.message
    assert error.retryable is False
    assert calls == 1, "non-retryable errors must not be retried"


@pytest.mark.parametrize("status", [429, 500, 503])
def test_retryable_http_errors_are_retried_with_backoff_then_succeed(tmp_path, status):
    attempts: list[float] = []

    async def flaky_agent(conversation, tools, context):
        attempts.append(time.perf_counter())
        if len(attempts) <= 2:
            raise TargetError(f"HTTP {status} from upstream", retryable=True, status_code=status)
        return "recovered answer"

    config = make_config(tmp_path, CASES[:1], run={"max_retries": 3, "retry_base_seconds": 0.05})
    result = run(make_runner(config, flaky_agent))

    assert len(attempts) == 3
    assert result.total_errors == 0
    sample = result.cases[0].samples[0]
    assert sample.error is None
    assert sample.transcript.turns[-1].content == "recovered answer"
    gaps = [b - a for a, b in zip(attempts, attempts[1:], strict=False)]
    assert all(gap >= 0.045 for gap in gaps), f"expected exponential backoff >= base, got {gaps}"


@pytest.mark.parametrize("status", [429, 500, 503])
def test_always_failing_retryable_error_ends_as_retryable_trial_error(tmp_path, status):
    attempts = 0

    async def down_agent(conversation, tools, context):
        nonlocal attempts
        attempts += 1
        raise TargetError(f"HTTP {status} from upstream", retryable=True, status_code=status)

    config = make_config(tmp_path, CASES[:1], run={"max_retries": 2, "retry_base_seconds": 0.01})
    result = run(make_runner(config, down_agent))

    assert attempts == 3  # first try + max_retries
    assert not result.partial
    error = result.cases[0].samples[0].error
    assert error is not None
    assert error.type == "TargetError"
    assert error.retryable is True
    assert str(status) in error.message
    assert result.cases[0].status == CaseStatus.inconclusive


def test_connection_errors_are_retryable(tmp_path):
    attempts = 0

    async def reset_agent(conversation, tools, context) -> Any:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ConnectionResetError("connection reset by peer")
        return "ok"

    config = make_config(tmp_path, CASES[:1], run={"max_retries": 1, "retry_base_seconds": 0.01})
    result = run(make_runner(config, reset_agent))
    assert attempts == 2
    assert result.total_errors == 0


def test_more_than_20_percent_errored_trials_make_case_inconclusive(tmp_path):
    # FI-TST-001: 2/5 trials error (40% > 20%) -> inconclusive even though all valid trials leak.
    # FI-TST-002: 1/5 trials error (20%, not above the limit) -> still decided (fail).
    async def partly_broken(conversation, tools, context):
        failing = {"FI-TST-001": {0, 1}, "FI-TST-002": {0}}[context.case_id]
        if context.trial_index in failing:
            raise RuntimeError("intermittent failure")
        return "Leaking: " + context.system_prompt

    config = make_config(tmp_path, CASES, run={"trials_per_case": 5})
    result = run(make_runner(config, partly_broken))
    by_id = {c.case_id: c for c in result.cases}
    assert by_id["FI-TST-001"].n_errors == 2
    assert by_id["FI-TST-001"].n_trials == 3
    assert by_id["FI-TST-001"].n_violations == 3
    assert by_id["FI-TST-001"].status == CaseStatus.inconclusive
    assert by_id["FI-TST-002"].n_errors == 1
    assert by_id["FI-TST-002"].n_trials == 4
    assert by_id["FI-TST-002"].status == CaseStatus.failed
