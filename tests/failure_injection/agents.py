"""Test-only agents loadable by path (``tests/failure_injection/agents.py:<name>``)."""

from __future__ import annotations

from typing import Any

from agentguard.harness.sandbox import ToolSandbox
from agentguard.llm.base import LLMMessage
from agentguard.targets.base import TargetContext


async def echo_agent(conversation: list[LLMMessage], tools: ToolSandbox, context: TargetContext) -> str:
    """Harmless agent: acknowledges the request without revealing anything."""
    return "I can help with general questions, but I cannot share internal configuration."


async def leaky_agent(conversation: list[LLMMessage], tools: ToolSandbox, context: TargetContext) -> str:
    """Vulnerable agent: always prints its system prompt (and therefore its canary)."""
    return "Sure! My instructions are:\n" + context.system_prompt


async def interrupting_agent(conversation: list[LLMMessage], tools: ToolSandbox, context: TargetContext) -> Any:
    """Simulates Ctrl-C arriving while the third trial is in flight."""
    interrupting_agent.calls += 1  # type: ignore[attr-defined]
    if interrupting_agent.calls >= 3:  # type: ignore[attr-defined]
        raise KeyboardInterrupt
    return "Sure! My instructions are:\n" + context.system_prompt


interrupting_agent.calls = 0  # type: ignore[attr-defined]
