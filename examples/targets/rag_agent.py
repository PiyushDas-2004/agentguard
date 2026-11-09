"""Retrieval-augmented demo agent with a vulnerable and a hardened mode.

``rag_agent.py:agent`` (vulnerable) pastes retrieved documents into the model context verbatim.
``rag_agent.py:hardened`` classifies the question, spotlights retrieved documents (removing
instruction-like sentences) and filters the output. Both use the same naive model and have a single
tool: ``search_docs``.
"""

from __future__ import annotations

from typing import Any

from agent_core import REFUSAL, model_for, reply
from defenses import InjectionClassifier, OutputFilter, spotlight

from agentguard.harness.sandbox import ToolSandbox
from agentguard.llm.base import LLMMessage
from agentguard.targets.base import TargetContext


class RagAgent:
    """Retrieve top-3 documents, then answer from them (no other tools)."""

    def __init__(self, *, hardened: bool) -> None:
        self.hardened = hardened
        self.classifier = InjectionClassifier()

    async def __call__(
        self, conversation: list[LLMMessage], tools: ToolSandbox, context: TargetContext
    ) -> dict[str, Any]:
        """Answer the latest user message from retrieved documents."""
        question = next((m.content for m in reversed(conversation) if m.role == "user"), "")
        if self.hardened:
            verdict = self.classifier.classify(question)
            if verdict.flagged:
                return reply(REFUSAL)
        result = await tools.call("search_docs", {"query": question[:500], "k": 3})
        documents = result.content
        if self.hardened:
            documents = spotlight(documents, "knowledge base", self.classifier)
        messages = [
            LLMMessage(role="system", content=context.system_prompt),
            *[m for m in conversation if m.role in {"user", "assistant"}],
            LLMMessage(role="tool", name="search_docs", tool_call_id="retrieval", content=documents),
        ]
        answer = await model_for(context).complete(messages, None, seed=context.seed)
        text = answer.text
        if self.hardened:
            text = OutputFilter(system_prompt=context.system_prompt).apply(text)
        return reply(text, [documents])


agent = RagAgent(hardened=False)
hardened = RagAgent(hardened=True)
