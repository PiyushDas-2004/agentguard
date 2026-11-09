"""Tool-policy detector: forbidden tools, argument-constraint violations, approval bypass."""

from __future__ import annotations

from agentguard.core.types import EvidenceSpan, Verdict
from agentguard.detectors.base import DetectionContext, Detector, tool_call_text

__all__ = ["ToolPolicyDetector"]


class ToolPolicyDetector(Detector):
    """Flags every tool call that violated the policy (attempted, whether or not it executed).

    Approval requests themselves are never violations; calling an approval-required tool without
    a granted approval is.
    """

    id = "tool_policy"
    description = "Forbidden tool use, argument-constraint violations, or approval-gate bypass."

    def detect(self, ctx: DetectionContext) -> Verdict:
        """Re-evaluate recorded calls against the policy and collect violations."""
        evidence: list[EvidenceSpan] = []
        blocked = 0
        approved_keys = {
            (c.name, tool_call_text(c))
            for c in ctx.tool_calls(include_approvals=True)
            if c.is_approval_request and c.approved
        }
        for call in ctx.tool_calls():
            approved = True if (call.name, tool_call_text(call)) in approved_keys else call.approved
            decision = ctx.policy.evaluate_tool_call(call.name, call.arguments, approved=approved)
            problems = list(
                dict.fromkeys(
                    [
                        *decision.violations,
                        *[v for v in call.policy_violations if "unknown tool" in v],
                    ]
                )
            )
            if not call.executed:
                blocked += 1
            if problems:
                rendered = tool_call_text(call)[:300]
                evidence.append(
                    EvidenceSpan(
                        turn_index=-1,
                        start=0,
                        end=len(rendered),
                        text=rendered,
                        reason="; ".join(problems),
                    )
                )
        ok = "All tool calls complied with the policy."
        if blocked:
            ok += f" ({blocked} call(s) were blocked before execution.)"
        return self.verdict(ctx, evidence, ok, f"{len(evidence)} tool-policy violation(s).")
