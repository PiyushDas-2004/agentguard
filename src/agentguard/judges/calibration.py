"""Judge calibration against the hand-labelled gold set (``agentguard calibrate-judge``)."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentguard.core.errors import DatasetError
from agentguard.judges.base import Judge, JudgeRequest

__all__ = [
    "BinaryMetrics",
    "CalibrationReport",
    "GoldExample",
    "binary_metrics",
    "calibrate",
    "cohen_kappa",
    "load_gold_set",
]

KAPPA_TARGET = 0.70


class GoldExample(BaseModel):
    """One hand-labelled judge example (``label`` = violated per the rubric)."""

    model_config = ConfigDict(extra="forbid")

    id: str
    rubric: str
    user_input: str
    response: str
    context: str = ""
    reference: str = ""
    objective: str = ""
    success_patterns: list[str] = Field(default_factory=list)
    label: bool
    rationale: str = ""


class BinaryMetrics(BaseModel):
    """Confusion matrix and derived metrics (positive class = violated)."""

    n: int
    tp: int
    fp: int
    tn: int
    fn: int
    accuracy: float
    precision: float
    recall: float
    f1: float
    kappa: float


class CalibrationReport(BaseModel):
    """Calibration results overall and per rubric."""

    judge_id: str
    overall: BinaryMetrics
    per_rubric: dict[str, BinaryMetrics]
    inconclusive: int = 0
    disagreements: list[str] = Field(default_factory=list)
    meets_target: bool
    kappa_target: float = KAPPA_TARGET


def load_gold_set(path: str | Path) -> list[GoldExample]:
    """Load the JSONL gold set.

    Raises:
        DatasetError: on invalid JSON or schema violations (with line numbers).
    """
    file = Path(path)
    if not file.exists():
        raise DatasetError(f"gold set not found: {file}")
    examples: list[GoldExample] = []
    for number, line in enumerate(file.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            examples.append(GoldExample.model_validate(json.loads(line)))
        except (json.JSONDecodeError, ValidationError) as exc:
            raise DatasetError(f"{file}:{number}: {exc}") from exc
    ids = [e.id for e in examples]
    if len(ids) != len(set(ids)):
        raise DatasetError(f"{file}: duplicate example ids")
    return examples


def cohen_kappa(tp: int, fp: int, tn: int, fn: int) -> float:
    """Cohen's kappa for two binary raters (judge vs. gold)."""
    n = tp + fp + tn + fn
    if n == 0:
        return 0.0
    observed = (tp + tn) / n
    p_yes = ((tp + fp) / n) * ((tp + fn) / n)
    p_no = ((tn + fn) / n) * ((tn + fp) / n)
    expected = p_yes + p_no
    if expected == 1.0:
        return 1.0 if observed == 1.0 else 0.0
    return (observed - expected) / (1 - expected)


def binary_metrics(pairs: Sequence[tuple[bool, bool]]) -> BinaryMetrics:
    """Compute metrics from ``(predicted, actual)`` pairs."""
    tp = sum(1 for p, a in pairs if p and a)
    fp = sum(1 for p, a in pairs if p and not a)
    tn = sum(1 for p, a in pairs if not p and not a)
    fn = sum(1 for p, a in pairs if not p and a)
    n = len(pairs)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return BinaryMetrics(
        n=n,
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        accuracy=round((tp + tn) / n, 4) if n else 0.0,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        kappa=round(cohen_kappa(tp, fp, tn, fn), 4),
    )


async def calibrate(judge: Judge, gold: Sequence[GoldExample]) -> CalibrationReport:
    """Run ``judge`` on every gold example; inconclusive verdicts count as wrong answers."""
    pairs: list[tuple[bool, bool]] = []
    per_rubric: dict[str, list[tuple[bool, bool]]] = {}
    inconclusive = 0
    disagreements: list[str] = []
    for example in gold:
        result = await judge.judge(
            JudgeRequest(
                rubric=example.rubric,
                user_input=example.user_input,
                response=example.response,
                context=example.context,
                reference=example.reference,
                objective=example.objective,
                success_patterns=example.success_patterns,
            )
        )
        if result.violated is None:
            inconclusive += 1
            predicted = not example.label
        else:
            predicted = result.violated
        if predicted != example.label:
            disagreements.append(example.id)
        pairs.append((predicted, example.label))
        per_rubric.setdefault(example.rubric, []).append((predicted, example.label))
    overall = binary_metrics(pairs)
    return CalibrationReport(
        judge_id=judge.id,
        overall=overall,
        per_rubric={rubric: binary_metrics(p) for rubric, p in sorted(per_rubric.items())},
        inconclusive=inconclusive,
        disagreements=disagreements,
        meets_target=overall.kappa >= KAPPA_TARGET,
    )
