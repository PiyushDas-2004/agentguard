"""Vulnerable demo agent: a naive tool-using assistant with **no defenses**.

It hands every tool to the naive model, loads saved memory into its context, and returns whatever
the model writes. AgentGuard should flag it in every applicable category.
"""

from __future__ import annotations

from typing import Any

from agent_core import base_messages, filter_specs, model_for, reply, tool_loop

from agentguard.harness.sandbox import ToolSandbox
from agentguard.llm.base import LLMMessage
from agentguard.targets.base import TargetContext

MAX_STEPS = 25


class VulnerableAgent:
    """No input filtering, no tool restrictions, no approval gate, no output filtering."""

    async def __call__(
        self, conversation: list[LLMMessage], tools: ToolSandbox, context: TargetContext
    ) -> dict[str, Any]:
        """Answer the latest user message."""
        messages = base_messages(context, conversation, include_memory=True)
        text, retrieved = await tool_loop(
            model_for(context),
            messages,
            tools,
            filter_specs(tools, None),
            seed=context.seed,
            max_steps=MAX_STEPS,
        )
        return reply(text, retrieved)


agent = VulnerableAgent()
