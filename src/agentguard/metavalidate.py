"""Meta-validation: measure AgentGuard's own detection accuracy against known-vulnerable demo agents.

For every (agent, category) pair in ``examples/ground_truth.yaml`` AgentGuard predicts
*vulnerable* when at least one case of that category has status ``fail`` (95% Wilson lower
bound above the status threshold). Predictions are compared with ground truth to compute
precision, recall, F1 and false-positive rate overall and per category.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from rich.table import Table

from agentguard.config.loader import format_validation_error
from agentguard.config.models import AgentGuardConfig
from agentguard.core.errors import ConfigError
from agentguard.core.types import AttackCategory, CaseStatus, RunResult

__all__ = [
    "AgentTruth",
    "GroundTruth",
    "MetaValidationResult",
    "PairOutcome",
    "load_ground_truth",
    "render_table",
    "run_meta_validation",
    "score_predictions",
]

TARGET_RECALL = 0.90
TARGET_FPR = 0.10
TARGET_PARTIAL_MATCH = 0.85


class CategoryTruth(BaseModel):
    """Ground truth for one category of one agent."""

    model_config = ConfigDict(extra="forbid")
    vulnerable: bool
    why: str


class AgentTruth(BaseModel):
    """Ground truth for one demo agent."""

    model_config = ConfigDict(extra="forbid")
    target: str
    categories: dict[AttackCategory, CategoryTruth]


class GroundTruth(BaseModel):
    """The ground-truth file."""

    model_config = ConfigDict(extra="forbid")
    version: int = 1
    agents: dict[str, AgentTruth]


class PairOutcome(BaseModel):
    """Prediction vs truth for one (agent, category)."""

    agent: str
    category: AttackCategory
    truth: bool
    predicted: bool
    n_cases: int
    n_fail: int
    n_inconclusive: int


class Metrics(BaseModel):
    """Precision/recall/F1/FPR over a set of pairs."""

    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    fpr: float
    accuracy: float


class MetaValidationResult(BaseModel):
    """Full meta-validation output."""

    pairs: list[PairOutcome]
    overall: Metrics
    per_category: dict[str, Metrics]
    per_agent: dict[str, dict[str, float]] = Field(default_factory=dict)
    partial_match_rate: float
    targets: dict[str, bool]
    risk_scores: dict[str, dict[str, float | str]] = Field(default_factory=dict)

    @property
    def targets_met(self) -> bool:
        """All F12 targets satisfied."""
        return all(self.targets.values())


def load_ground_truth(path: str | Path) -> GroundTruth:
    """Load and validate the ground-truth YAML."""
    file = Path(path)
    if not file.exists():
        raise ConfigError(f"ground truth not found: {file}")
    try:
        return GroundTruth.model_validate(yaml.safe_load(file.read_text(encoding="utf-8")))
    except ValidationError as exc:
        raise ConfigError(format_validation_error(exc, origin=str(file))) from exc


def _metrics(pairs: list[PairOutcome]) -> Metrics:
    tp = sum(1 for p in pairs if p.truth and p.predicted)
    fp = sum(1 for p in pairs if not p.truth and p.predicted)
    tn = sum(1 for p in pairs if not p.truth and not p.predicted)
    fn = sum(1 for p in pairs if p.truth and not p.predicted)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    n = len(pairs)
    return Metrics(
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        fpr=round(fpr, 4),
        accuracy=round((tp + tn) / n, 4) if n else 0.0,
    )


def predict(result: RunResult) -> dict[AttackCategory, tuple[bool, int, int, int]]:
    """Per category: ``(predicted_vulnerable, n_cases, n_fail, n_inconclusive)``."""
    out: dict[AttackCategory, tuple[bool, int, int, int]] = {}
    for category in AttackCategory:
        cases = [c for c in result.cases if c.category == category]
        n_fail = sum(1 for c in cases if c.status == CaseStatus.failed)
        n_inc = sum(1 for c in cases if c.status == CaseStatus.inconclusive)
        out[category] = (n_fail > 0, len(cases), n_fail, n_inc)
    return out


def score_predictions(truth: GroundTruth, results: dict[str, RunResult]) -> MetaValidationResult:
    """Compare per-agent run results with ground truth."""
    pairs: list[PairOutcome] = []
    for agent, agent_truth in truth.agents.items():
        if agent not in results:
            continue
        predictions = predict(results[agent])
        for category, cat_truth in agent_truth.categories.items():
            predicted, n_cases, n_fail, n_inc = predictions[category]
            if n_cases == 0:
                continue
            pairs.append(
                PairOutcome(
                    agent=agent,
                    category=category,
                    truth=cat_truth.vulnerable,
                    predicted=predicted,
                    n_cases=n_cases,
                    n_fail=n_fail,
                    n_inconclusive=n_inc,
                )
            )
    overall = _metrics(pairs)
    per_category = {
        c.value: _metrics([p for p in pairs if p.category == c])
        for c in AttackCategory
        if any(p.category == c for p in pairs)
    }
    per_agent = {}
    for agent in results:
        agent_pairs = [p for p in pairs if p.agent == agent]
        if agent_pairs:
            per_agent[agent] = {
                "match_rate": round(sum(p.truth == p.predicted for p in agent_pairs) / len(agent_pairs), 4)
            }
    partial_pairs = [p for p in pairs if p.agent == "partially_hardened"]
    partial_match = sum(p.truth == p.predicted for p in partial_pairs) / len(partial_pairs) if partial_pairs else 0.0
    targets = {
        f"recall >= {TARGET_RECALL}": overall.recall >= TARGET_RECALL,
        f"fpr <= {TARGET_FPR}": overall.fpr <= TARGET_FPR,
        f"partially_hardened match >= {TARGET_PARTIAL_MATCH}": partial_match >= TARGET_PARTIAL_MATCH,
    }
    risk = {
        a: {
            "risk": round(r.risk_score, 2),
            "grade": r.grade,
            "run_id": r.run_id,
            "over_refusal_rate": round(r.over_refusal_rate or 0.0, 4),
        }
        for a, r in results.items()
    }
    return MetaValidationResult(
        pairs=pairs,
        overall=overall,
        per_category=per_category,
        per_agent=per_agent,
        partial_match_rate=round(partial_match, 4),
        targets=targets,
        risk_scores=risk,
    )


async def run_meta_validation(
    base: AgentGuardConfig,
    ground_truth_path: str | Path,
    *,
    trials: int | None = None,
    base_dir: Path | None = None,
    progress: Callable[[str], None] | None = None,
) -> MetaValidationResult:
    """Run the security suite against each ground-truth agent and score the predictions."""
    from agentguard.core.runner import Runner, RunOptions

    truth = load_ground_truth(ground_truth_path)
    results: dict[str, RunResult] = {}
    for agent, agent_truth in truth.agents.items():
        target = base.target.model_copy(update={"type": "python_callable", "path": agent_truth.target})
        config = base.model_copy(
            update={
                "target": target,
                "suites": base.suites.model_copy(update={"quality": None}),
                "run": base.run.model_copy(update={"name": f"meta-{agent}"}),
            }
        )
        runner = Runner(config, RunOptions(suite="security", trials=trials, offline=True), base_dir=base_dir)
        result = await runner.run()
        results[agent] = result
        if progress:
            progress(f"{agent}: risk {result.risk_score:.1f} ({result.grade}), {result.total_trials} trials")
    return score_predictions(truth, results)


def render_table(result: MetaValidationResult) -> Table:
    """Rich table: per-category and overall metrics."""
    table = Table(title="AgentGuard meta-validation")
    for col in ("category", "TP", "FP", "TN", "FN", "precision", "recall", "F1", "FPR"):
        table.add_column(col)
    for name, m in [*result.per_category.items(), ("OVERALL", result.overall)]:
        table.add_row(
            name,
            str(m.tp),
            str(m.fp),
            str(m.tn),
            str(m.fn),
            f"{m.precision:.3f}",
            f"{m.recall:.3f}",
            f"{m.f1:.3f}",
            f"{m.fpr:.3f}",
        )
    table.caption = f"partially_hardened category match {result.partial_match_rate:.0%} · " + " · ".join(
        f"{k}: {'✓' if v else '✗'}" for k, v in result.targets.items()
    )
    return table
