"""Tool sandbox: validates, policy-checks, approves, executes (mock) and records every tool call."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import BaseModel

from agentguard.config.policy import Policy
from agentguard.core.types import ToolCall
from agentguard.harness.environment import VirtualEnvironment
from agentguard.harness.tools import (
    TOOL_REGISTRY,
    ToolArgumentError,
    ToolSpec,
    canonical_args,
    execute_tool,
)
from agentguard.llm.base import LLMToolSpec

__all__ = ["Approver", "ToolResult", "ToolSandbox", "static_approver"]

Approver = Callable[[str, dict[str, Any]], Awaitable[bool]]


def static_approver(decision: bool) -> Approver:
    """Return an approver that always answers ``decision`` (the default denies)."""

    async def approve(name: str, arguments: dict[str, Any]) -> bool:
        return decision

    return approve


class ToolResult(BaseModel):
    """Outcome of a sandboxed tool call."""

    content: str
    error: bool = False
    call: ToolCall


class ToolSandbox:
    """Mediates every tool call a target makes.

    In ``observe`` mode (default) policy-violating calls are still simulated so downstream agent
    behaviour (e.g. exfiltrating what it just read) stays observable; the violation is recorded on
    the :class:`ToolCall`. In ``block`` mode violating calls are not executed.

    Args:
        env: virtual environment the mock tools act on.
        policy: security policy.
        tool_names: tools exposed to the target (defaults to every registered tool).
        approver: async callback deciding approval requests (defaults to the policy default).
        max_result_chars: truncation limit of tool results returned to the target.
    """

    def __init__(
        self,
        env: VirtualEnvironment,
        policy: Policy,
        *,
        tool_names: list[str] | None = None,
        approver: Approver | None = None,
        max_result_chars: int = 8000,
    ) -> None:
        self.env = env
        self.policy = policy
        names = tool_names if tool_names is not None else list(TOOL_REGISTRY)
        self._tools: dict[str, ToolSpec] = {n: TOOL_REGISTRY[n] for n in names if n in TOOL_REGISTRY}
        self.approver = approver or static_approver(policy.approver_default == "approve")
        self.max_result_chars = max_result_chars
        self.calls: list[ToolCall] = []
        self._approvals: dict[tuple[str, str], bool] = {}
        self.turn_index = 0
        self.session = 1

    # ------------------------------------------------------------------ specs
    def specs(self) -> list[ToolSpec]:
        """Tool specs exposed to the target."""
        return list(self._tools.values())

    def llm_specs(self) -> list[LLMToolSpec]:
        """Tool specs in LLM format."""
        return [spec.to_llm() for spec in self._tools.values()]

    @property
    def names(self) -> list[str]:
        """Names of exposed tools."""
        return list(self._tools)

    # ------------------------------------------------------------------ approvals
    async def request_approval(self, name: str, arguments: dict[str, Any]) -> bool:
        """Ask the (mock) human approver; the decision is recorded and remembered for the call."""
        decision = bool(await self.approver(name, arguments))
        self._approvals[(name, canonical_args(arguments))] = decision
        self.calls.append(
            ToolCall(
                name=name,
                arguments=dict(arguments),
                allowed=decision,
                approval_required=True,
                approved=decision,
                executed=False,
                is_approval_request=True,
                result_preview="approved" if decision else "approval denied",
                turn_index=self.turn_index,
                session=self.session,
            )
        )
        return decision

    # ------------------------------------------------------------------ calls
    async def call(self, name: str, arguments: dict[str, Any] | None = None) -> ToolResult:
        """Execute a tool call through validation, policy and (simulated) execution."""
        arguments = dict(arguments or {})
        approved = self._approvals.get((name, canonical_args(arguments)))
        decision = self.policy.evaluate_tool_call(name, arguments, approved=approved)
        violations = list(decision.violations)
        if name not in self._tools:
            if name not in TOOL_REGISTRY:
                violations.append(f"unknown tool '{name}'")
            else:
                violations.append(f"tool '{name}' is not exposed to this target")
            content, error, executed = f"Error: tool '{name}' is not available.", True, False
        elif violations and self.policy.mode == "block":
            content = "Error: blocked by policy: " + "; ".join(violations)
            error, executed = True, False
        else:
            try:
                content = execute_tool(self.env, name, arguments)
                error, executed = content.startswith("Error:"), True
            except ToolArgumentError as exc:
                content, error, executed = f"Error: {exc}", True, False
        if len(content) > self.max_result_chars:
            content = content[: self.max_result_chars] + "\n[truncated]"
        call = ToolCall(
            name=name,
            arguments=arguments,
            allowed=not violations,
            approval_required=decision.approval_required,
            approved=approved,
            executed=executed,
            policy_violations=violations,
            result_preview=content[:300],
            turn_index=self.turn_index,
            session=self.session,
        )
        self.calls.append(call)
        return ToolResult(content=content, error=error, call=call)

    def record_external(self, name: str, arguments: dict[str, Any], result: str | None = None) -> ToolCall:
        """Record a tool call the target executed itself (HTTP/MCP targets) for policy analysis."""
        decision = self.policy.evaluate_tool_call(name, arguments, approved=None)
        call = ToolCall(
            name=name,
            arguments=dict(arguments),
            allowed=decision.allowed,
            approval_required=decision.approval_required,
            approved=None,
            executed=True,
            policy_violations=list(decision.violations),
            result_preview=(result or "")[:300],
            turn_index=self.turn_index,
            session=self.session,
        )
        self.calls.append(call)
        return call
