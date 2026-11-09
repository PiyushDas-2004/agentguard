"""Provider-neutral LLM message, tool and response types."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Literal

from pydantic import BaseModel, Field

__all__ = ["BaseLLM", "LLMMessage", "LLMResponse", "LLMToolCall", "LLMToolSpec", "estimate_tokens"]


def estimate_tokens(text: str) -> int:
    """Rough token estimate (~4 characters per token), never below 1 for non-empty text."""
    if not text:
        return 0
    return max(1, len(text) // 4)


class LLMToolCall(BaseModel):
    """A tool call proposed by a model."""

    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class LLMMessage(BaseModel):
    """A chat message.

    Attributes:
        role: chat role.
        content: message text.
        name: optional label; for ``system`` messages AgentGuard demo agents use ``context`` for
            deployment context and ``memory`` for saved memory notes.
        tool_call_id: id of the call a ``tool`` message answers.
        tool_calls: calls proposed by an ``assistant`` message.
    """

    role: Literal["system", "user", "assistant", "tool"]
    content: str = ""
    name: str | None = None
    tool_call_id: str | None = None
    tool_calls: list[LLMToolCall] = Field(default_factory=list)


class LLMToolSpec(BaseModel):
    """A tool definition offered to a model (JSON-schema parameters)."""

    name: str
    description: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class LLMResponse(BaseModel):
    """A model completion with accounting metadata."""

    text: str = ""
    tool_calls: list[LLMToolCall] = Field(default_factory=list)
    model: str = "unknown"
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    raw: Any = None


class BaseLLM(ABC):
    """Abstract chat-completion client."""

    model_name: str = "unknown"

    @abstractmethod
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
        """Return a completion for ``messages`` (optionally offering ``tools``)."""
