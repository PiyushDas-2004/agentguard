"""Quality-task and RAG-QA dataset models and loaders."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentguard.config.loader import format_validation_error
from agentguard.core.errors import DatasetError

__all__ = ["ExpectedCall", "QualityTask", "RagQuestion", "SuccessCheck", "load_rag_questions", "load_tasks"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ExpectedCall(_Strict):
    """An expected tool call; ``args`` values are regexes matched against ``str(value)``."""

    tool: str
    args: dict[str, str] = Field(default_factory=dict)


class SuccessCheck(_Strict):
    """Deterministic (or judge-based) success criterion for a task."""

    type: Literal["output_contains", "output_regex", "tool_called", "judge"]
    value: str = ""


class QualityTask(_Strict):
    """A tool-use task with its expected trajectory."""

    id: str
    goal: str
    expected_trajectory: list[ExpectedCall] = Field(default_factory=list)
    success: SuccessCheck
    reference: str = ""
    tags: list[str] = Field(default_factory=list)


class RagQuestion(_Strict):
    """A knowledge-base question with reference answer and relevant documents."""

    id: str
    question: str
    reference_answer: str
    relevant_docs: list[str] = Field(min_length=1)


class _TaskFile(_Strict):
    tasks: list[QualityTask]


class _RagFile(_Strict):
    questions: list[RagQuestion]


def _load(path: str | Path, model: type[BaseModel]) -> BaseModel:
    file = Path(path)
    if not file.exists():
        raise DatasetError(f"dataset not found: {file}")
    try:
        data = yaml.safe_load(file.read_text(encoding="utf-8"))
        return model.model_validate(data)
    except yaml.YAMLError as exc:
        raise DatasetError(f"{file}: invalid YAML: {exc}") from exc
    except ValidationError as exc:
        raise DatasetError(format_validation_error(exc, origin=str(file))) from exc


def load_tasks(path: str | Path) -> list[QualityTask]:
    """Load ``tasks.yaml``."""
    result = _load(path, _TaskFile)
    assert isinstance(result, _TaskFile)
    ids = [t.id for t in result.tasks]
    if len(ids) != len(set(ids)):
        raise DatasetError(f"{path}: duplicate task ids")
    return result.tasks


def load_rag_questions(path: str | Path) -> list[RagQuestion]:
    """Load ``rag_qa.yaml``."""
    result = _load(path, _RagFile)
    assert isinstance(result, _RagFile)
    return result.questions
