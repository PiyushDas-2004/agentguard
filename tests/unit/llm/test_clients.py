"""BudgetTracker, factory, base helpers and the LiteLLM client (litellm boundary stubbed)."""

from __future__ import annotations

import asyncio
import json
import sys
import types
from typing import Any

import pytest
import tenacity

from agentguard.config.models import LLMConfig
from agentguard.core.errors import BudgetExceededError, ConfigError, TargetError
from agentguard.llm import litellm_client
from agentguard.llm.base import LLMMessage, LLMToolCall, LLMToolSpec, estimate_tokens
from agentguard.llm.budget import BudgetTracker
from agentguard.llm.factory import build_llm
from agentguard.llm.litellm_client import LiteLLMClient, _to_litellm_messages, is_retryable_llm_error
from agentguard.llm.mock import MockLLM


class TestEstimateTokens:
    def test_values(self) -> None:
        assert estimate_tokens("") == 0
        assert estimate_tokens("abc") == 1
        assert estimate_tokens("a" * 40) == 10


class TestBudget:
    def test_uncapped(self) -> None:
        b = BudgetTracker()
        b.charge(100.0)
        assert b.remaining is None
        assert not b.exceeded
        assert BudgetTracker(max_cost_usd=0).remaining is None

    def test_charge_and_breakdown(self) -> None:
        b = BudgetTracker(max_cost_usd=1.0)
        b.charge(0.25, "target")
        b.charge(0.25, "judge")
        b.charge(0.25, "judge")
        assert b.calls == 3
        assert b.by_component == {"target": 0.25, "judge": 0.5}
        assert b.remaining == pytest.approx(0.25)

    def test_exactly_at_cap_is_ok_above_raises(self) -> None:
        b = BudgetTracker(max_cost_usd=1.0)
        b.charge(1.0)
        assert not b.exceeded
        with pytest.raises(BudgetExceededError, match=r"spent \$1.5000 > cap \$1.0000"):
            b.charge(0.5)
        assert b.exceeded
        assert b.remaining == 0.0

    def test_negative_cost(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            BudgetTracker().charge(-1)


class TestFactory:
    def test_mock(self) -> None:
        llm = build_llm(LLMConfig(provider="mock", profile="attacker", injection_compliance=0.3), seed=4)
        assert isinstance(llm, MockLLM)
        assert llm.profile == "attacker"
        assert llm.seed == 4
        assert llm.injection_compliance == 0.3

    def test_offline_forces_mock(self) -> None:
        llm = build_llm(LLMConfig(provider="anthropic", profile="attacker"), offline=True)
        assert isinstance(llm, MockLLM)
        assert llm.profile == "vulnerable"

    def test_live(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "x")
        llm = build_llm(LLMConfig(provider="openai", model="gpt-x", temperature=0.5, api_base="http://b"))
        assert isinstance(llm, LiteLLMClient)
        assert llm.model == "gpt-x"
        assert llm.temperature == 0.5
        assert llm.api_base == "http://b"


# --------------------------------------------------------------------------- LiteLLM boundary stub


class FakeRateLimitError(Exception):
    pass


class FakeStatusError(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(f"status {status}")
        self.status_code = status


def _ns(**kwargs: Any) -> types.SimpleNamespace:
    return types.SimpleNamespace(**kwargs)


def _raw(content: str | None = "hello", tool_calls: list | None = None, usage: Any = None) -> Any:
    message = _ns(content=content, tool_calls=tool_calls)
    return _ns(choices=[_ns(message=message)], usage=usage)


class FakeLiteLLM(types.ModuleType):
    def __init__(self, responses: list[Any], cost: float | Exception = 0.0123) -> None:
        super().__init__("litellm")
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []
        self.cost = cost

    async def acompletion(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def completion_cost(self, completion_response: Any) -> float:
        if isinstance(self.cost, Exception):
            raise self.cost
        return self.cost


@pytest.fixture
def no_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(litellm_client, "backoff", lambda *_a, **_k: tenacity.wait_none())


def install(monkeypatch: pytest.MonkeyPatch, fake: FakeLiteLLM) -> FakeLiteLLM:
    monkeypatch.setitem(sys.modules, "litellm", fake)
    return fake


@pytest.fixture
def keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    monkeypatch.setenv("OPENAI_API_KEY", "test")


class TestRetryable:
    @pytest.mark.parametrize(
        ("exc", "expected"),
        [
            (FakeStatusError(429), True),
            (FakeStatusError(503), True),
            (FakeStatusError(400), False),
            (FakeRateLimitError(), True),
            (type("APIConnectionError", (Exception,), {})(), True),
            (type("Timeout", (Exception,), {})(), True),
            (type("InternalServerError", (Exception,), {})(), True),
            (type("ServiceUnavailableError", (Exception,), {})(), True),
            (ValueError("x"), False),
        ],
    )
    def test_classification(self, exc: BaseException, expected: bool) -> None:
        assert is_retryable_llm_error(exc) is expected


class TestLiteLLMClient:
    def test_missing_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(ConfigError, match="ANTHROPIC_API_KEY"):
            LiteLLMClient("anthropic")

    def test_unknown_provider_needs_model(self) -> None:
        with pytest.raises(ConfigError, match="needs an explicit model"):
            LiteLLMClient("litellm")

    def test_model_strings(self, keys: None) -> None:
        assert LiteLLMClient("anthropic").litellm_model == "anthropic/claude-sonnet-5-5"
        assert LiteLLMClient("ollama").litellm_model == "ollama/llama3.1"
        assert LiteLLMClient("openai", "azure/gpt").litellm_model == "azure/gpt"
        assert LiteLLMClient("litellm", "bedrock-x").litellm_model == "bedrock-x"
        assert LiteLLMClient("openai").model_name == "gpt-4o-mini"

    def test_message_conversion(self) -> None:
        msgs = [
            LLMMessage(role="system", content="s"),
            LLMMessage(role="assistant", tool_calls=[LLMToolCall(id="c1", name="f", arguments={"a": 1})]),
            LLMMessage(role="tool", content="r"),
            LLMMessage(role="tool", content="r2", tool_call_id="c1"),
        ]
        out = _to_litellm_messages(msgs)
        assert out[0] == {"role": "system", "content": "s"}
        assert out[1]["tool_calls"][0] == {
            "id": "c1",
            "type": "function",
            "function": {"name": "f", "arguments": json.dumps({"a": 1})},
        }
        assert out[2]["tool_call_id"] == "call"
        assert out[3]["tool_call_id"] == "c1"

    def test_success_with_tool_calls(self, monkeypatch: pytest.MonkeyPatch, keys: None) -> None:
        calls = [
            _ns(id="t1", function=_ns(name="http_get", arguments='{"url": "https://x"}')),
            _ns(id="t2", function=_ns(name="noop", arguments=None)),
            _ns(id="t3", function=_ns(name="bad", arguments="{not json")),
        ]
        fake = install(
            monkeypatch,
            FakeLiteLLM([_raw(None, calls, _ns(prompt_tokens=11, completion_tokens=7))]),
        )
        client = LiteLLMClient("openai", "gpt-x", api_base="http://base", temperature=0.3)
        resp = asyncio.run(
            client.complete(
                [LLMMessage(role="user", content="hi")],
                [LLMToolSpec(name="http_get", description="d", parameters={"type": "object"})],
                seed=5,
                json_mode=True,
                max_tokens=50,
            )
        )
        assert resp.text == ""
        assert [(c.id, c.name, c.arguments) for c in resp.tool_calls] == [
            ("t1", "http_get", {"url": "https://x"}),
            ("t2", "noop", {}),
            ("t3", "bad", {"_raw": "{not json"}),
        ]
        assert (resp.tokens_in, resp.tokens_out) == (11, 7)
        assert resp.cost_usd == pytest.approx(0.0123)
        assert resp.model == "gpt-x"
        kwargs = fake.calls[0]
        assert kwargs["model"] == "openai/gpt-x"
        assert kwargs["api_base"] == "http://base"
        assert kwargs["seed"] == 5
        assert kwargs["max_tokens"] == 50
        assert kwargs["temperature"] == 0.3
        assert kwargs["response_format"] == {"type": "json_object"}
        assert kwargs["tools"][0]["function"]["name"] == "http_get"

    def test_anthropic_omits_openai_only_kwargs(self, monkeypatch: pytest.MonkeyPatch, keys: None) -> None:
        fake = install(monkeypatch, FakeLiteLLM([_raw("ok")], cost=RuntimeError("no price")))
        resp = asyncio.run(
            LiteLLMClient("anthropic").complete(
                [LLMMessage(role="user", content="q")], seed=1, json_mode=True, temperature=0.9
            )
        )
        assert resp.text == "ok"
        assert resp.cost_usd == 0.0
        assert resp.tokens_in == 0
        kwargs = fake.calls[0]
        assert "seed" not in kwargs
        assert "response_format" not in kwargs
        assert "tools" not in kwargs
        assert kwargs["temperature"] == 0.9

    def test_retries_retryable_then_succeeds(self, monkeypatch: pytest.MonkeyPatch, keys: None, no_wait: None) -> None:
        fake = install(monkeypatch, FakeLiteLLM([FakeRateLimitError("slow"), FakeStatusError(502), _raw("finally")]))
        resp = asyncio.run(LiteLLMClient("openai").complete([LLMMessage(role="user", content="q")]))
        assert resp.text == "finally"
        assert len(fake.calls) == 3

    def test_retries_exhausted(self, monkeypatch: pytest.MonkeyPatch, keys: None, no_wait: None) -> None:
        fake = install(monkeypatch, FakeLiteLLM([FakeStatusError(500)] * 3))
        client = LiteLLMClient("openai", max_retries=2)
        with pytest.raises(TargetError, match="LLM call failed") as info:
            asyncio.run(client.complete([LLMMessage(role="user", content="q")]))
        assert info.value.retryable
        assert len(fake.calls) == 3

    def test_non_retryable_not_retried(self, monkeypatch: pytest.MonkeyPatch, keys: None, no_wait: None) -> None:
        fake = install(monkeypatch, FakeLiteLLM([FakeStatusError(401), _raw("never")]))
        with pytest.raises(TargetError) as info:
            asyncio.run(LiteLLMClient("openai").complete([LLMMessage(role="user", content="q")]))
        assert not info.value.retryable
        assert len(fake.calls) == 1
