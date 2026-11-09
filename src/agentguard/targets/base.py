"""Target abstraction shared by every adapter."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from agentguard.core.types import ToolCall
from agentguard.harness.memory import MemoryStore
from agentguard.harness.rag_fixture import RagIndex
from agentguard.harness.sandbox import ToolSandbox
from agentguard.llm.base import BaseLLM, LLMMessage, LLMResponse, LLMToolSpec
from agentguard.llm.budget import BudgetTracker

__all__ = ["BaseTarget", "LLMCallRecord", "MeteredLLM", "TargetContext", "TargetResponse"]


class TargetResponse(BaseModel):
    """What a target returns for one user turn.

    Attributes:
        text: the assistant's visible reply.
        tool_calls: tool calls the target reports having executed itself (HTTP/MCP targets);
            calls made through the sandbox are recorded automatically.
        tokens_in / tokens_out / cost_usd: usage the target reports (added to metered usage).
        model: model identifier if known.
        retrieved_contexts: documents the target retrieved (for RAG metrics).
    """

    text: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    model: str | None = None
    retrieved_contexts: list[str] = Field(default_factory=list)
    raw: Any = None


@dataclass
class LLMCallRecord:
    """Usage of one metered LLM call."""

    model: str
    tokens_in: int
    tokens_out: int
    cost_usd: float
    latency_ms: float


class MeteredLLM(BaseLLM):
    """Wraps an LLM to charge the run budget and record usage per call."""

    def __init__(self, inner: BaseLLM, budget: BudgetTracker | None = None, component: str = "target") -> None:
        self.inner = inner
        self.budget = budget
        self.component = component
        self.model_name = inner.model_name
        self.records: list[LLMCallRecord] = []

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
        """Delegate to the wrapped model, then record usage and charge the budget."""
        if self.budget is not None:
            self.budget.check()
        started = time.perf_counter()
        response = await self.inner.complete(
            messages,
            tools,
            seed=seed,
            temperature=temperature,
            json_mode=json_mode,
            max_tokens=max_tokens,
        )
        latency = response.latency_ms or (time.perf_counter() - started) * 1000
        self.records.append(
            LLMCallRecord(response.model, response.tokens_in, response.tokens_out, response.cost_usd, latency)
        )
        if self.budget is not None:
            self.budget.charge(response.cost_usd, self.component)
        return response

    def drain(self) -> list[LLMCallRecord]:
        """Return and clear the recorded calls."""
        records, self.records = self.records, []
        return records


@dataclass
class TargetContext:
    """Per-trial context handed to targets.

    Attributes:
        run_id / case_id / trial_index / seed / session: trial identity.
        llm: the model a Python demo agent should use (metered), if configured.
        system_prompt: rendered system prompt (with its canary) the agent should adopt.
        system_context: extra deployment context (the ``system_context`` injection vector).
        memory: cross-session memory store.
        rag: retrieval index (with any per-trial poisoned documents).
        timeout_seconds: per-turn timeout.
        extra: free-form options from ``target.options``.
    """

    run_id: str
    case_id: str
    trial_index: int
    seed: int
    session: int = 1
    llm: MeteredLLM | None = None
    system_prompt: str = ""
    system_context: str | None = None
    memory: MemoryStore = field(default_factory=MemoryStore)
    rag: RagIndex = field(default_factory=lambda: RagIndex([]))
    timeout_seconds: float = 30.0
    extra: dict[str, Any] = field(default_factory=dict)


class BaseTarget(ABC):
    """Base class of all target adapters."""

    type_name: str = "base"

    @property
    def name(self) -> str:
        """Display name of the target."""
        return self.type_name

    def describe(self) -> dict[str, Any]:
        """Non-secret details for the report's metadata appendix."""
        return {}

    async def start(self) -> None:  # noqa: B027 - optional hook
        """Optional async setup (open connections, spawn servers)."""

    async def aclose(self) -> None:  # noqa: B027 - optional hook
        """Optional async teardown."""

    @abstractmethod
    async def send(self, conversation: list[LLMMessage], tools: ToolSandbox, context: TargetContext) -> TargetResponse:
        """Send the conversation so far (ending with a user turn) and return the reply."""
