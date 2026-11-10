"""Builders for scoring tests (real core.types models)."""

from __future__ import annotations

from datetime import UTC, datetime

from agentguard.core.types import (
    AttackCategory,
    CaseResult,
    CaseStatus,
    ErrorInfo,
    RunResult,
    Severity,
    TargetInfo,
    Trial,
    Verdict,
)
from agentguard.scoring.aggregate import TrialRecord, category_scorecards
from agentguard.scoring.risk import case_status, grade, overall_risk, risk_contribution
from agentguard.scoring.stats import wilson_interval


def case_result(
    case_id: str = "CASE-001",
    *,
    k: int = 0,
    n: int = 10,
    severity: Severity = Severity.high,
    category: AttackCategory = AttackCategory.PI_DIRECT,
    owasp: list[str] | None = None,
    status: CaseStatus | None = None,
) -> CaseResult:
    """A CaseResult whose CI/status/risk are computed from ``k``/``n`` like aggregate_case does."""
    low, high = wilson_interval(k, n)
    return CaseResult(
        case_id=case_id,
        category=category,
        owasp_llm=list(owasp or []),
        n_trials=n,
        n_errors=0,
        n_violations=k,
        violation_rate=k / n if n else 0.0,
        ci_low=low,
        ci_high=high,
        severity=severity,
        risk_contribution=risk_contribution(severity, high),
        status=status or case_status(low, high, n_valid=n),
    )


def run_result(run_id: str, cases: list[CaseResult]) -> RunResult:
    """A RunResult with categories, risk and grade derived from ``cases``."""
    risk = overall_risk(cases)
    return RunResult(
        run_id=run_id,
        name=run_id,
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        target=TargetInfo(type="mock", name="mock"),
        config_hash="x",
        agentguard_version="0",
        seed=1,
        trials_per_case=10,
        fail_threshold_risk=25.0,
        cases=cases,
        categories=category_scorecards(cases),
        risk_score=risk,
        grade=grade(risk),
    )


def record(
    index: int,
    violated: bool | None,
    *,
    mutation: str | None = None,
    error: bool = False,
    inconclusive: bool = False,
    objective_met: bool | None = None,
    detectors: tuple[str, ...] = (),
) -> TrialRecord:
    """A finished trial record."""
    trial = Trial(
        run_id="run",
        case_id="CASE-001",
        trial_index=index,
        seed=index,
        mutation_id=mutation,
        error=ErrorInfo(type="TargetError", message="boom") if error else None,
        violated=None if (error or inconclusive) else violated,
        inconclusive=inconclusive,
        objective_met=objective_met,
    )
    verdicts = [
        Verdict(detector_id=d, trial_id=trial.trial_id, violated=bool(violated), confidence=1.0) for d in detectors
    ]
    return TrialRecord(trial=trial, verdicts=verdicts)
