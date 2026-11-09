"""Live LLM client backed by LiteLLM (Anthropic, OpenAI, Ollama, ...).

LiteLLM is an optional extra (``agentguard[litellm]``) and is imported lazily so offline runs never
touch it. Retries use exponential backoff with jitter on rate limits, 5xx and timeouts.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from tenacity import AsyncRetrying, retry_if_exception, stop_after_attempt, wait_exponential_jitter

from agentguard.core.errors import ConfigError, TargetError
from agentguard.llm.base import BaseLLM, LLMMessage, LLMResponse, LLMToolCall, LLMToolSpec

__all__ = ["PROVIDER_KEYS", "LiteLLMClient", "is_retryable_llm_error"]

PROVIDER_KEYS: dict[str, str] = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}
DEFAULT_MODELS: dict[str, str] = {
    "anthropic": "claude-sonnet-5-5",
    "openai": "gpt-4o-mini",
    "ollama": "llama3.1",
}


def is_retryable_llm_error(exc: BaseException) -> bool:
    """Rate limits, 5xx responses, timeouts and connection errors are retryable."""
    status = getattr(exc, "status_code", None)
    if isinstance(status, int) and (status == 429 or status >= 500):
        return True
    name = type(exc).__name__.lower()
    return any(
        token in name
        for token in (
            "ratelimit",
            "timeout",
            "serviceunavailable",
            "apiconnection",
            "internalserver",
        )
    )


def _to_litellm_messages(messages: list[LLMMessage]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in messages:
        item: dict[str, Any] = {"role": m.role, "content": m.content}
        if m.role == "tool":
            item["tool_call_id"] = m.tool_call_id or "call"
        if m.tool_calls:
            item["tool_calls"] = [
                {
                    "id": c.id,
                    "type": "function",
                    "function": {"name": c.name, "arguments": json.dumps(c.arguments)},
                }
                for c in m.tool_calls
            ]
        out.append(item)
    return out


class LiteLLMClient(BaseLLM):
    """LiteLLM-backed client.

    Args:
        provider: ``anthropic``, ``openai``, ``ollama`` or ``litellm`` (model string passed as-is).
        model: model id (defaults per provider).
        api_base: optional base URL.
        temperature: default temperature.
        max_retries: retry attempts for retryable errors.
    """

    def __init__(
        self,
        provider: str,
        model: str | None = None,
        *,
        api_base: str | None = None,
        temperature: float = 0.0,
        max_retries: int = 4,
    ) -> None:
        self.provider = provider
        self.model = model or DEFAULT_MODELS.get(provider, "")
        if not self.model:
            raise ConfigError(f"judge/target llm: provider {provider!r} needs an explicit model")
        self.api_base = api_base
        self.temperature = temperature
        self.max_retries = max_retries
        self.model_name = self.model
        key = PROVIDER_KEYS.get(provider)
        if key and not os.environ.get(key):
            raise ConfigError(f"provider {provider!r} requires the {key} environment variable")

    @property
    def litellm_model(self) -> str:
        """Model string in LiteLLM's ``provider/model`` form."""
        if self.provider == "litellm" or "/" in self.model:
            return self.model
        return f"{self.provider}/{self.model}"

    async def complete(
        self,
        messages: list[LLMMessage],
        tools: list[LLMToolSpec] | None = None,
        *,
        seed: int | None = None,
        temperature: float | None = None,
        json_mode: bool = False,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        """Call the provider through LiteLLM with retries."""
        os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
        try:
            import litellm
        except ImportError as exc:  # pragma: no cover - depends on installed extras
            raise ConfigError("live providers need the extra: pip install 'agentguard[litellm]'") from exc
        kwargs: dict[str, Any] = {
            "model": self.litellm_model,
            "messages": _to_litellm_messages(messages),
            "temperature": self.temperature if temperature is None else temperature,
        }
        if self.api_base:
            kwargs["api_base"] = self.api_base
        if seed is not None and self.provider == "openai":
            kwargs["seed"] = seed
        if max_tokens is not None:
            kwargs["max_tokens"] = max_tokens
        if json_mode and self.provider == "openai":
            kwargs["response_format"] = {"type": "json_object"}
        if tools:
            kwargs["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    },
                }
                for t in tools
            ]
        started = time.perf_counter()
        retrying = AsyncRetrying(
            stop=stop_after_attempt(self.max_retries + 1),
            wait=wait_exponential_jitter(initial=1.0, max=30.0),
            retry=retry_if_exception(is_retryable_llm_error),
            reraise=True,
        )
        try:
            async for attempt in retrying:
                with attempt:
                    raw = await litellm.acompletion(**kwargs)
        except Exception as exc:
            raise TargetError(f"LLM call failed: {exc}", retryable=is_retryable_llm_error(exc)) from exc
        return self._parse(raw, (time.perf_counter() - started) * 1000, litellm)

    def _parse(self, raw: Any, latency_ms: float, litellm: Any) -> LLMResponse:
        choice = raw.choices[0].message
        calls: list[LLMToolCall] = []
        for call in getattr(choice, "tool_calls", None) or []:
            try:
                args = json.loads(call.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {"_raw": call.function.arguments}
            calls.append(LLMToolCall(id=call.id, name=call.function.name, arguments=args))
        usage = getattr(raw, "usage", None)
        try:
            cost = float(litellm.completion_cost(completion_response=raw))
        except Exception:
            cost = 0.0
        return LLMResponse(
            text=choice.content or "",
            tool_calls=calls,
            model=self.model,
            tokens_in=int(getattr(usage, "prompt_tokens", 0) or 0),
            tokens_out=int(getattr(usage, "completion_tokens", 0) or 0),
            cost_usd=cost,
            latency_ms=latency_ms,
            raw=None,
        )
