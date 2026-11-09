"""Shared plumbing for the AgentGuard demo agents.

Every demo agent wraps the *same* naive, instruction-following ``MockLLM`` (profile
``vulnerable``). Agents differ only in the defense code around the model, which is what makes
AgentGuard's meta-validation meaningful.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from agentguard.harness.sandbox import ToolSandbox
from agentguard.llm.base import BaseLLM, LLMMessage, LLMToolSpec
from agentguard.llm.mock import MockLLM
from agentguard.targets.base import TargetContext

REFUSAL = "I'm sorry, but I can't help with that request."


def model_for(context: TargetContext) -> BaseLLM:
    """The model configured by AgentGuard for this trial (falls back to the naive mock)."""
    if context.llm is not None:
        return context.llm
    return MockLLM("vulnerable", seed=context.seed)


def base_messages(context: TargetContext, conversation: list[LLMMessage], *, include_memory: bool) -> list[LLMMessage]:
    """System prompt + deployment context (+ saved memory) + the conversation."""
    messages = [LLMMessage(role="system", content=context.system_prompt)]
    if context.system_context:
        messages.append(
            LLMMessage(
                role="system",
                name="context",
                content="Deployment context:\n" + context.system_context,
            )
        )
    if include_memory and context.memory.items():
        messages.append(
            LLMMessage(
                role="system",
                name="memory",
                content="Saved memory notes:\n" + context.memory.render(),
            )
        )
    messages.extend(conversation)
    return messages


def filter_specs(tools: ToolSandbox, allowed: Iterable[str] | None) -> list[LLMToolSpec]:
    """Tool specs offered to the model, optionally restricted to an allowlist."""
    specs = tools.llm_specs()
    if allowed is None:
        return specs
    allow = set(allowed)
    return [s for s in specs if s.name in allow]


async def tool_loop(
    llm: BaseLLM,
    messages: list[LLMMessage],
    tools: ToolSandbox,
    specs: list[LLMToolSpec],
    *,
    seed: int,
    max_steps: int,
    allowed: Iterable[str] | None = None,
) -> tuple[str, list[str]]:
    """Classic ReAct-style loop: let the model call tools until it answers.

    Returns:
        ``(answer_text, retrieved_document_texts)``.
    """
    allow = set(allowed) if allowed is not None else None
    retrieved: list[str] = []
    for _ in range(max_steps):
        response = await llm.complete(messages, specs, seed=seed)
        if not response.tool_calls:
            return response.text, retrieved
        messages.append(LLMMessage(role="assistant", tool_calls=response.tool_calls))
        for call in response.tool_calls:
            if allow is not None and call.name not in allow:
                content = f"Error: tool '{call.name}' is not available."
            else:
                result = await tools.call(call.name, call.arguments)
                content = result.content
                if call.name == "search_docs":
                    retrieved.append(content)
            messages.append(LLMMessage(role="tool", name=call.name, tool_call_id=call.id, content=content))
    final = await llm.complete(messages, None, seed=seed)
    return final.text, retrieved


def reply(text: str, retrieved: list[str] | None = None) -> dict[str, Any]:
    """Shape an agent reply for the PythonCallableTarget adapter."""
    return {"text": text, "retrieved_contexts": retrieved or []}
