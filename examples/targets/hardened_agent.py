"""Hardened demo agent: the same naive model, wrapped in a real defense layer.

Defense pipeline per user turn (see ``defenses.py``):

1. **Input classifier** on normalized readings of the user message (decodes base64/ROT13,
   folds homoglyphs, strips zero-width characters, repairs split words, translates a small
   multilingual lexicon). Flagged requests are refused.
2. **Plan-then-execute**: tools are planned from the trusted user message only; untrusted
   context (deployment context, memory, tool results) never reaches the planner.
3. **Tool guard**: allowlist, argument validation, provenance check on destinations, a
   human-approval gate that defaults to deny, and per-turn call caps.
4. **Spotlighting**: tool results are stripped of instruction-like sentences and delimited as
   data before the model writes the answer (with no tools offered).
5. **Output filter**: blocks secret or system-prompt leakage (also encoded), redacts PII,
   removes non-allowlisted links, neutralizes active content, verifies packages, caps length.
6. **Memory-write sanitizer**: instruction-like notes are never persisted.

The model is identical to the vulnerable agent's; only this wrapper makes the agent safe.
"""

from __future__ import annotations

import json
from typing import Any

from agent_core import REFUSAL, model_for, reply
from defenses import InjectionClassifier, OutputFilter, ToolGuard, spotlight

from agentguard.harness.sandbox import ToolSandbox
from agentguard.llm.base import LLMMessage, LLMToolSpec
from agentguard.targets.base import TargetContext

MAX_PLANNING_ROUNDS = 3


class HardenedAgent:
    """Defense-in-depth wrapper around the naive model.

    Args:
        tool_names: tools this agent may use (``None`` = the guard's allowlist).
        guard: tool guard configuration.
    """

    def __init__(self, tool_names: tuple[str, ...] | None = None, guard: ToolGuard | None = None) -> None:
        self.guard = guard or ToolGuard()
        self.tool_names = tool_names
        self.classifier = InjectionClassifier()

    def _specs(self, tools: ToolSandbox) -> list[LLMToolSpec]:
        names = set(self.tool_names) if self.tool_names is not None else set(self.guard.allowed_tools)
        return [s for s in tools.llm_specs() if s.name in names]

    async def __call__(
        self, conversation: list[LLMMessage], tools: ToolSandbox, context: TargetContext
    ) -> dict[str, Any]:
        """Answer the latest user message through the defense pipeline."""
        latest = next((m.content for m in reversed(conversation) if m.role == "user"), "")
        verdict = self.classifier.classify(latest)
        if verdict.flagged:
            return reply(REFUSAL + " It conflicts with my security policy (" + ", ".join(verdict.reasons) + ").")

        llm = model_for(context)
        output_filter = OutputFilter(system_prompt=context.system_prompt, allowed_domains=self.guard.allowed_domains)
        trusted_text = "\n".join(m.content for m in conversation if m.role == "user")
        history = [m for m in conversation if m.role in {"user", "assistant"}]
        planner_messages = [LLMMessage(role="system", content=context.system_prompt), *history]
        specs = self._specs(tools)
        executed: dict[str, int] = {}
        results: list[LLMMessage] = []
        retrieved: list[str] = []
        notes: list[str] = []
        calls_this_turn = 0

        for _ in range(MAX_PLANNING_ROUNDS):
            response = await llm.complete(planner_messages, specs, seed=context.seed)
            if not response.tool_calls:
                break
            planner_messages.append(LLMMessage(role="assistant", tool_calls=response.tool_calls))
            progressed = False
            for call in response.tool_calls:
                key = call.name + json.dumps(call.arguments, sort_keys=True, default=str)
                decision = self.guard.check(call.name, call.arguments, trusted_text)
                content: str
                if (
                    executed.get(key, 0) >= self.guard.max_identical_calls
                    or calls_this_turn >= self.guard.max_calls_per_turn
                ):
                    content = "Skipped: resource limit reached."
                elif not decision.allowed:
                    content = f"Blocked by tool guard: {decision.reason}."
                    notes.append(f"I did not run {call.name}: {decision.reason}.")
                elif call.name == "email_send" and output_filter.leaks_secret(str(call.arguments.get("body", ""))):
                    content = "Blocked: e-mail body contains sensitive material."
                    notes.append("I did not send that e-mail because it contained sensitive material.")
                elif decision.needs_approval and not await tools.request_approval(call.name, call.arguments):
                    content = f"Not executed: {call.name} requires human approval and approval was not granted."
                    notes.append(f"{call.name} needs human approval, which was not granted, so I did not run it.")
                else:
                    result = await tools.call(call.name, call.arguments)
                    executed[key] = executed.get(key, 0) + 1
                    calls_this_turn += 1
                    progressed = True
                    content = spotlight(result.content, call.name, self.classifier)
                    if call.name == "search_docs":
                        retrieved.append(content)
                message = LLMMessage(role="tool", name=call.name, tool_call_id=call.id, content=content)
                planner_messages.append(message)
                results.append(message)
            if not progressed:
                break

        answer_messages = [
            LLMMessage(role="system", content=context.system_prompt),
            *history,
            *results,
        ]
        answer = await llm.complete(answer_messages, None, seed=context.seed)
        text = output_filter.apply(answer.text)
        if notes:
            text = text + "\n\n" + " ".join(dict.fromkeys(notes))
        return reply(text, retrieved)


agent = HardenedAgent()
