"""OpenAI-compatible chat-completions target with function calling.

AgentGuard acts as the tool executor: tool calls the model requests are run in the sandbox and the
results are fed back until the model answers (or ``max_tool_steps`` is reached).
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx

from agentguard.config.models import TargetConfig
from agentguard.core.errors import ConfigError, TargetError
from agentguard.harness.sandbox import ToolSandbox
from agentguard.llm.base import LLMMessage
from agentguard.targets.base import BaseTarget, TargetContext, TargetResponse
from agentguard.targets.http import RETRYABLE_STATUS

__all__ = ["OpenAICompatibleTarget"]


class OpenAICompatibleTarget(BaseTarget):
    """Target for any ``/v1/chat/completions`` endpoint (OpenAI, vLLM, Ollama, LM Studio...).

    Args:
        base_url: API base URL (``.../v1``) or a full ``/chat/completions`` URL.
        model: model name.
        api_key: bearer token (optional).
        max_tool_steps: maximum tool round-trips per user turn.
        send_system_prompt: prepend AgentGuard's system prompt (with canary) as a system message.
        transport: optional httpx transport (tests).
    """

    type_name = "openai_compat"

    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        api_key: str | None = None,
        max_tool_steps: int = 8,
        send_system_prompt: bool = True,
        timeout: float = 60.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        url = base_url.rstrip("/")
        self.url = url if url.endswith("/chat/completions") else url + "/chat/completions"
        self.model = model
        self.api_key = api_key
        self.max_tool_steps = max_tool_steps
        self.send_system_prompt = send_system_prompt
        self.timeout = timeout
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    @classmethod
    def from_config(cls, config: TargetConfig) -> OpenAICompatibleTarget:
        """Build from a ``TargetConfig`` (``api_key_env`` names the key variable)."""
        assert config.url is not None
        key = os.environ.get(config.api_key_env) if config.api_key_env else None
        if config.api_key_env and not key:
            raise ConfigError(f"target.api_key_env: environment variable {config.api_key_env} is not set")
        return cls(
            config.url,
            config.model or config.llm.model or "gpt-4o-mini",
            api_key=key,
            max_tool_steps=config.max_tool_steps,
            send_system_prompt=bool(config.options.get("send_system_prompt", True)),
            timeout=float(config.options.get("timeout", 60.0)),
        )

    @property
    def name(self) -> str:
        """Display name."""
        return f"{self.model} @ {self.url}"

    def describe(self) -> dict[str, Any]:
        """Report metadata."""
        return {"url": self.url, "model": self.model, "max_tool_steps": self.max_tool_steps}

    async def start(self) -> None:
        """Open the HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout, transport=self._transport)

    async def aclose(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        assert self._client is not None
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        try:
            response = await self._client.post(self.url, json=payload, headers=headers)
        except httpx.TimeoutException as exc:
            raise TargetError(f"timeout calling {self.url}: {exc}", retryable=True) from exc
        except httpx.HTTPError as exc:
            raise TargetError(f"HTTP error calling {self.url}: {exc}", retryable=True) from exc
        if response.status_code >= 400:
            raise TargetError(
                f"HTTP {response.status_code} from {self.url}",
                retryable=response.status_code in RETRYABLE_STATUS,
                status_code=response.status_code,
            )
        try:
            data = response.json()
        except json.JSONDecodeError as exc:
            raise TargetError("non-JSON response from chat completions endpoint") from exc
        if not isinstance(data, dict) or not data.get("choices"):
            raise TargetError("malformed chat completion: missing 'choices'")
        return data

    async def send(self, conversation: list[LLMMessage], tools: ToolSandbox, context: TargetContext) -> TargetResponse:
        """Run the chat-completions tool loop for the latest user turn."""
        await self.start()
        messages: list[dict[str, Any]] = []
        if self.send_system_prompt and context.system_prompt:
            messages.append({"role": "system", "content": context.system_prompt})
        if context.system_context:
            messages.append({"role": "system", "content": context.system_context})
        messages.extend({"role": m.role, "content": m.content} for m in conversation)
        tool_specs = [
            {"type": "function", "function": {"name": s.name, "description": s.description, "parameters": s.parameters}}
            for s in tools.llm_specs()
        ]
        tokens_in = tokens_out = 0
        for _ in range(self.max_tool_steps + 1):
            payload: dict[str, Any] = {"model": self.model, "messages": messages}
            if tool_specs:
                payload["tools"] = tool_specs
            data = await self._post(payload)
            usage = data.get("usage") or {}
            tokens_in += int(usage.get("prompt_tokens", 0) or 0)
            tokens_out += int(usage.get("completion_tokens", 0) or 0)
            message = data["choices"][0].get("message") or {}
            calls = message.get("tool_calls") or []
            if not calls:
                return TargetResponse(
                    text=message.get("content") or "",
                    tokens_in=tokens_in,
                    tokens_out=tokens_out,
                    model=data.get("model", self.model),
                )
            messages.append({"role": "assistant", "content": message.get("content") or "", "tool_calls": calls})
            for call in calls:
                function = call.get("function") or {}
                try:
                    arguments = json.loads(function.get("arguments") or "{}")
                except json.JSONDecodeError:
                    arguments = {}
                result = await tools.call(
                    str(function.get("name", "")), arguments if isinstance(arguments, dict) else {}
                )
                messages.append({"role": "tool", "tool_call_id": call.get("id", "call"), "content": result.content})
        return TargetResponse(
            text="[agentguard] tool step limit reached", tokens_in=tokens_in, tokens_out=tokens_out, model=self.model
        )
