"""Judge interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from importlib import resources
from typing import Literal

from pydantic import BaseModel, Field

__all__ = ["RUBRICS", "Judge", "JudgeOutput", "JudgeRequest", "JudgeResult", "load_rubric"]

RubricId = Literal["jailbreak", "task_success", "faithfulness", "refusal"]
RUBRICS: tuple[str, ...] = ("jailbreak", "task_success", "faithfulness", "refusal")


def load_rubric(rubric_id: str) -> str:
    """Return the markdown rubric text for ``rubric_id``."""
    if rubric_id not in RUBRICS:
        raise KeyError(f"unknown rubric {rubric_id!r}")
    return resources.files("agentguard.judges.rubrics").joinpath(f"{rubric_id}.md").read_text(encoding="utf-8")


class JudgeRequest(BaseModel):
    """What the judge is asked to evaluate.

    ``violated`` semantics per rubric: ``jailbreak`` — the response complied with the attack;
    ``task_success`` — the task was NOT accomplished; ``faithfulness`` — the answer contains claims
    unsupported by the context; ``refusal`` — a legitimate request was refused.
    """

    rubric: RubricId
    user_input: str
    response: str
    context: str = ""
    reference: str = ""
    objective: str = ""
    success_patterns: list[str] = Field(default_factory=list)
    case_id: str | None = None


class JudgeOutput(BaseModel):
    """Structured JSON a judge must produce."""

    violated: bool
    score: float = Field(ge=0.0, le=1.0)
    rationale: str


class JudgeResult(BaseModel):
    """A judge decision (``violated`` is ``None`` when inconclusive)."""

    judge_id: str
    rubric: str
    violated: bool | None
    score: float = 0.0
    rationale: str = ""
    raw: str = ""
    attempts: int = 1
    inconclusive: bool = False
    cost_usd: float = 0.0


class Judge(ABC):
    """Base judge."""

    id: str = "judge"

    @abstractmethod
    async def judge(self, request: JudgeRequest) -> JudgeResult:
        """Evaluate one request."""
