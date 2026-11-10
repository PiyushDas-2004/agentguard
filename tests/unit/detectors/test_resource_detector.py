"""ResourceDetector: limits from the example policy (15 calls, 5 identical, 20k chars, 30k tokens,
12 turns, 60 s)."""

from __future__ import annotations

import pytest

from agentguard.detectors.resource import ResourceDetector
from tests.unit.detectors._helpers import call, make_ctx


def _detect(policy, assistant="ok", **kw):  # type: ignore[no-untyped-def]
    return ResourceDetector().detect(make_ctx(policy, assistant, **kw))


def _distinct_calls(n: int):  # type: ignore[no-untyped-def]
    return [call("db_query", table="orders", where={"id": i}) for i in range(n)]


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"tool_calls": _distinct_calls(16)}, "16 tool calls > limit 15"),
        ({"tool_calls": [call("file_read", path="/a")] * 6}, "identical call repeated 6x > limit 5"),
        ({"assistant": "x" * 20_001}, "reply of 20001 chars > limit 20000"),
        ({"original_output_chars": 50_000}, "reply of 50000 chars > limit 20000"),
        ({"tokens": (20_000, 10_001)}, "30001 tokens > limit 30000"),
        ({"assistant": ["a"] * 13, "user": ["u"] * 13}, "13 turns > limit 12"),
        ({"wall_time_s": 60.5}, "wall time 60.5s > limit 60.0s"),
    ],
)
def test_limit_exceeded(policy, kwargs: dict, reason: str) -> None:
    verdict = _detect(policy, **kwargs)
    assert verdict.violated
    assert reason in [e.reason for e in verdict.evidence]
    assert verdict.explanation == "Resource limits exceeded."


@pytest.mark.parametrize(
    "kwargs",
    [
        {"tool_calls": _distinct_calls(15)},
        {"tool_calls": [call("file_read", path="/a")] * 5},
        {"assistant": "x" * 20_000},
        {"original_output_chars": 20_000},
        {"tokens": (20_000, 10_000)},
        {"assistant": ["a"] * 12, "user": ["u"] * 12},
        {"wall_time_s": 60.0},
        {"tool_calls": []},
        {"assistant": None},
    ],
)
def test_at_or_below_limit(policy, kwargs: dict) -> None:
    verdict = _detect(policy, **kwargs)
    assert not verdict.violated, verdict.evidence
    assert verdict.explanation == "Resource use within limits."


def test_identical_calls_compare_arguments(policy) -> None:
    calls = [call("file_read", path=f"/sandbox/public/{i % 2}.txt") for i in range(10)]
    assert not _detect(policy, tool_calls=calls).violated


def test_identical_call_evidence_shows_the_call(policy) -> None:
    verdict = _detect(policy, tool_calls=[call("http_get", url="https://acme.example/")] * 7)
    span = verdict.evidence[0]
    assert span.text.startswith("http_get(")
    assert span.end == len(span.text)


def test_approval_requests_do_not_count(policy) -> None:
    requests = [call("payment_transfer", amount=i).model_copy(update={"is_approval_request": True}) for i in range(20)]
    assert not _detect(policy, tool_calls=requests).violated


def test_all_exceeded_limits_are_reported(policy) -> None:
    verdict = _detect(
        policy,
        assistant="x" * 30_000,
        tool_calls=[call("file_read", path="/a")] * 20,
        tokens=(40_000, 0),
        wall_time_s=120,
    )
    assert len(verdict.evidence) == 5


def test_custom_limits() -> None:
    from agentguard.config.policy import Policy

    policy = Policy(limits={"max_tool_calls": 1, "max_identical_tool_calls": 1})
    verdict = _detect(policy, tool_calls=[call("a"), call("a")])
    assert len(verdict.evidence) == 2
