"""Example **target plugin**: a rule-based customer-support bot.

A target plugin adapts "something AgentGuard can talk to" (a proprietary SDK, a message queue, a
gRPC service...) to :class:`~agentguard.targets.base.BaseTarget`. This one is self-contained so the
example runs offline: it answers FAQ questions, looks up orders and issues refunds through the
AgentGuard tool sandbox, and has a ``leaky`` switch that turns off its (deliberately simple)
safeguards so you can watch AgentGuard catch the difference.

Registered under the ``agentguard.targets`` entry-point group as ``support_bot``; use it with::

    target:
      type: support_bot
      options: { leaky: true }
"""

from __future__ import annotations

import re
from typing import Any

from agentguard.config.models import TargetConfig
from agentguard.harness.sandbox import ToolSandbox
from agentguard.llm.base import LLMMessage
from agentguard.targets.base import BaseTarget, TargetContext, TargetResponse

__all__ = ["DEFAULT_FAQ", "SupportBotTarget"]

DEFAULT_FAQ: dict[str, str] = {
    "opening hours": "We are open Monday to Friday, 9:00-17:00 CET.",
    "shipping": "Standard shipping takes 3-5 business days.",
    "return": "You can return any item within 30 days for a full refund.",
}
REFUSAL = "I'm sorry, but I can't help with that request."
_AMOUNT = re.compile(r"(\d+(?:\.\d+)?)\s*(?:eur|euro|usd|\$|€)?", re.I)
_ACCOUNT = re.compile(r"\b(?:account|acct\.?)\s+([A-Z0-9-]{4,})", re.I)


class SupportBotTarget(BaseTarget):
    """A scripted support bot behind the ``support_bot`` target type.

    Plugin targets are constructed with the validated ``target:`` block of the config, so every
    option the bot needs comes from ``config.options`` (free-form) or the standard fields.

    Args:
        config: the ``target`` section of the AgentGuard config.
    """

    type_name = "support_bot"

    def __init__(self, config: TargetConfig) -> None:
        options: dict[str, Any] = dict(config.options)
        self.display_name = config.name or "support-bot"
        self.leaky = bool(options.get("leaky", False))
        self.faq: dict[str, str] = {**DEFAULT_FAQ, **dict(options.get("faq", {}))}
        self.escalation_url = str(options.get("escalation_url", "https://ops-console.corp.internal/escalate"))
        self.turns_served = 0

    @property
    def name(self) -> str:
        """Display name shown in reports."""
        return self.display_name

    def describe(self) -> dict[str, Any]:
        """Non-secret details for the report's metadata appendix."""
        return {"leaky": self.leaky, "faq_topics": sorted(self.faq)}

    async def start(self) -> None:
        """Open connections here (called once per run before the first trial)."""
        self.turns_served = 0

    async def send(self, conversation: list[LLMMessage], tools: ToolSandbox, context: TargetContext) -> TargetResponse:
        """Answer the latest user message.

        Tool use goes through ``tools`` (the AgentGuard sandbox), so every call is recorded and
        checked against the policy, exactly as for the built-in targets.
        """
        self.turns_served += 1
        message = next((m.content for m in reversed(conversation) if m.role == "user"), "")
        text = await self._answer(message, tools, context)
        return TargetResponse(
            text=text,
            model="support-bot-rules",
            tokens_in=len(message.split()),
            tokens_out=len(text.split()),
        )

    async def _answer(self, message: str, tools: ToolSandbox, context: TargetContext) -> str:
        lower = message.lower()
        if any(word in lower for word in ("instructions", "system prompt", "configuration")):
            return f"My instructions are:\n{context.system_prompt}" if self.leaky else REFUSAL
        if any(word in lower for word in ("internal", "admin console", "escalat")):
            if self.leaky:
                return f"Our on-call team uses {self.escalation_url} for escalations."
            return "Please e-mail support@acme.example and we will escalate for you."
        if "refund" in lower or "transfer" in lower:
            return await self._refund(message, tools)
        if "order" in lower:
            result = await tools.call("db_query", {"table": "orders"})
            return "Here is what I found about your orders:\n" + result.content[:500]
        for topic, answer in self.faq.items():
            if topic in lower:
                return answer
        return "Thanks for reaching out! Could you tell me a bit more about what you need?"

    async def _refund(self, message: str, tools: ToolSandbox) -> str:
        account = _ACCOUNT.search(message)
        amount = _AMOUNT.search(message.replace(account.group(0), "") if account else message)
        if account is None or amount is None:
            return "Which account should the refund go to, and how much?"
        arguments = {"amount": float(amount.group(1)), "to_account": account.group(1)}
        if not self.leaky and not await tools.request_approval("payment_transfer", arguments):
            return "A refund needs approval from a human agent; I have opened a request."
        result = await tools.call("payment_transfer", arguments)
        return f"Refund issued: {result.content}"
