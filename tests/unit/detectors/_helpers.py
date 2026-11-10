"""Builders for real :class:`DetectionContext` objects used by the detector unit tests."""

from __future__ import annotations

from typing import Any

from agentguard.config.policy import Policy
from agentguard.core.types import (
    AttackCase,
    AttackCategory,
    InjectionVector,
    Objective,
    ObjectiveType,
    Role,
    Severity,
    ToolCall,
    Transcript,
    TranscriptTurn,
    Trial,
    Turn,
)
from agentguard.detectors.base import DetectionContext
from agentguard.harness.canary import CanaryRegistry
from agentguard.harness.environment import PlantedPII


def make_case(
    detectors: list[str] | None = None,
    *,
    category: AttackCategory = AttackCategory.PI_DIRECT,
    objective: Objective | None = None,
    case_id: str = "TEST-001",
    severity: Severity = Severity.high,
) -> AttackCase:
    """A minimal valid user-message case."""
    return AttackCase(
        id=case_id,
        category=category,
        title="unit test case",
        description="a case built for unit tests",
        severity=severity,
        owasp_llm=["LLM01:2025"],
        vector=InjectionVector.user_message,
        turns=[Turn(content="please do the thing")],
        objective=objective or Objective(type=ObjectiveType.answered, description="answer"),
        detectors=detectors or ["canary"],
    )


def make_transcript(
    assistant: list[str] | str | None = None,
    *,
    user: list[str] | str | None = None,
    tool_calls: list[ToolCall] | None = None,
    tokens: tuple[int, int] = (0, 0),
) -> Transcript:
    """Alternate user/assistant turns (user first) and attach tool calls."""
    assistant_list = [assistant] if isinstance(assistant, str) else list(assistant or [])
    user_list = [user] if isinstance(user, str) else list(user or [])
    turns: list[TranscriptTurn] = []
    for i in range(max(len(assistant_list), len(user_list))):
        if i < len(user_list):
            turns.append(TranscriptTurn(index=len(turns), role=Role.user, content=user_list[i]))
        if i < len(assistant_list):
            turns.append(TranscriptTurn(index=len(turns), role=Role.assistant, content=assistant_list[i]))
    if turns and (tokens[0] or tokens[1]):
        turns[-1] = turns[-1].model_copy(update={"tokens_in": tokens[0], "tokens_out": tokens[1]})
    return Transcript(turns=turns, tool_calls=list(tool_calls or []))


def call(name: str, executed: bool = True, **arguments: Any) -> ToolCall:
    """A recorded tool call."""
    return ToolCall(name=name, arguments=arguments, executed=executed)


def make_ctx(
    policy: Policy,
    assistant: list[str] | str | None = None,
    *,
    user: list[str] | str | None = None,
    tool_calls: list[ToolCall] | None = None,
    canaries: CanaryRegistry | None = None,
    system_prompt: str = "",
    planted_pii: list[PlantedPII] | None = None,
    detectors: list[str] | None = None,
    tokens: tuple[int, int] = (0, 0),
    wall_time_s: float = 0.0,
    original_output_chars: int = 0,
) -> DetectionContext:
    """A real detection context around a synthetic transcript."""
    transcript = make_transcript(assistant, user=user, tool_calls=tool_calls, tokens=tokens)
    trial = Trial(run_id="run", case_id="TEST-001", trial_index=0, seed=7, transcript=transcript)
    return DetectionContext(
        trial=trial,
        case=make_case(detectors),
        policy=policy,
        canaries=canaries if canaries is not None else CanaryRegistry(seed=0),
        system_prompt=system_prompt,
        planted_pii=list(planted_pii or []),
        wall_time_s=wall_time_s,
        original_output_chars=original_output_chars,
    )
