"""SQLModel tables: runs, cases, trials, verdicts, judge_calls."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, Text
from sqlmodel import Field, SQLModel

__all__ = ["CaseRow", "JudgeCallRow", "RunRow", "TrialRow", "VerdictRow"]


class RunRow(SQLModel, table=True):
    """One AgentGuard run; ``result_json`` holds the full ``RunResult``."""

    __tablename__ = "runs"

    id: str = Field(primary_key=True)
    name: str
    started_at: datetime
    ended_at: datetime | None = None
    status: str = "running"
    partial: bool = False
    risk_score: float | None = None
    grade: str | None = None
    target_type: str = ""
    target_name: str = ""
    config_hash: str = ""
    result_json: str | None = Field(default=None, sa_column=Column(Text))


class CaseRow(SQLModel, table=True):
    """Aggregated result of one case in a run."""

    __tablename__ = "cases"

    id: int | None = Field(default=None, primary_key=True)
    run_id: str = Field(index=True)
    case_id: str = Field(index=True)
    category: str
    status: str
    n_trials: int
    n_violations: int
    violation_rate: float
    ci_low: float
    ci_high: float


class TrialRow(SQLModel, table=True):
    """One trial (transcript lives in the JSONL store)."""

    __tablename__ = "trials"

    id: str = Field(primary_key=True)
    run_id: str = Field(index=True)
    case_id: str = Field(index=True)
    trial_index: int
    mutation_id: str | None = None
    seed: int
    violated: bool | None = None
    inconclusive: bool = False
    objective_met: bool | None = None
    error_type: str | None = None
    error_message: str | None = None
    started_at: datetime
    ended_at: datetime | None = None


class VerdictRow(SQLModel, table=True):
    """A detector or judge verdict for a trial."""

    __tablename__ = "verdicts"

    id: int | None = Field(default=None, primary_key=True)
    run_id: str = Field(index=True)
    trial_id: str = Field(index=True)
    detector_id: str
    violated: bool
    confidence: float
    explanation: str = ""
    evidence_json: str = Field(default="[]", sa_column=Column(Text))


class JudgeCallRow(SQLModel, table=True):
    """Raw record of a judge invocation."""

    __tablename__ = "judge_calls"

    id: int | None = Field(default=None, primary_key=True)
    run_id: str = Field(index=True)
    trial_id: str
    judge_id: str
    rubric: str
    raw_output: str = Field(default="", sa_column=Column(Text))
    violated: bool | None = None
    attempts: int = 1
