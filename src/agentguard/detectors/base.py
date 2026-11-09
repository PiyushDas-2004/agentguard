"""Detector interface and the per-trial detection context."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from agentguard.config.policy import Policy
from agentguard.core.types import AttackCase, EvidenceSpan, Role, ToolCall, Trial, Verdict
from agentguard.harness.canary import CanaryRegistry
from agentguard.harness.environment import PlantedPII

__all__ = ["DetectionContext", "Detector", "tool_call_text"]


def tool_call_text(call: ToolCall) -> str:
    """Render a tool call as ``name(json-args)`` for scanning and evidence."""
    return f"{call.name}({json.dumps(call.arguments, sort_keys=True, default=str)})"


@dataclass
class DetectionContext:
    """Everything a detector may inspect about one trial.

    Attributes:
        trial: the trial (transcript, tool calls, error).
        case: the case that was run.
        policy: active policy.
        canaries: canaries planted for this trial.
        system_prompt: the system prompt the target was given (for leak detection).
        planted_pii: synthetic PII planted in the environment.
        untrusted_inputs: attacker-controlled text that reached the target (poison, user turns).
        wall_time_s: trial wall-clock time.
        original_output_chars: largest reply length before harness truncation.
    """

    trial: Trial
    case: AttackCase
    policy: Policy
    canaries: CanaryRegistry = field(default_factory=lambda: CanaryRegistry(seed=0))
    system_prompt: str = ""
    planted_pii: list[PlantedPII] = field(default_factory=list)
    untrusted_inputs: list[str] = field(default_factory=list)
    wall_time_s: float = 0.0
    original_output_chars: int = 0

    @property
    def trial_id(self) -> str:
        """Identifier of the trial under inspection."""
        return self.trial.trial_id

    def assistant_turns(self) -> list[tuple[int, str]]:
        """``(turn_index, text)`` of every assistant message."""
        return [(t.index, t.content) for t in self.trial.transcript.turns if t.role == Role.assistant]

    def user_text(self) -> str:
        """All user-authored text (things the target was given, not things it produced)."""
        return self.trial.transcript.user_text()

    def tool_calls(self, *, include_approvals: bool = False) -> list[ToolCall]:
        """Tool calls made by the target (approval requests excluded by default)."""
        return [c for c in self.trial.transcript.tool_calls if include_approvals or not c.is_approval_request]


class Detector(ABC):
    """Base class: subclasses set ``id``/``description`` and implement :meth:`detect`."""

    id: str = "base"
    description: str = ""

    @abstractmethod
    def detect(self, ctx: DetectionContext) -> Verdict:
        """Inspect the trial and return a verdict."""

    def verdict(
        self,
        ctx: DetectionContext,
        evidence: list[EvidenceSpan],
        explanation_ok: str,
        explanation_bad: str,
        *,
        confidence: float = 1.0,
    ) -> Verdict:
        """Build a verdict: violated iff ``evidence`` is non-empty."""
        violated = bool(evidence)
        return Verdict(
            detector_id=self.id,
            trial_id=ctx.trial_id,
            violated=violated,
            confidence=confidence if violated else 1.0,
            evidence=evidence[:20],
            explanation=explanation_bad if violated else explanation_ok,
        )
