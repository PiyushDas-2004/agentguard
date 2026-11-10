"""SQLite result store with retry on ``database is locked``."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from sqlalchemy.exc import OperationalError
from sqlmodel import Session, SQLModel, col, create_engine, select
from tenacity import retry, retry_if_exception, stop_after_attempt

from agentguard.core.errors import StorageError
from agentguard.core.retry import backoff
from agentguard.core.types import RunResult, Trial, Verdict
from agentguard.storage.models import CaseRow, JudgeCallRow, RunRow, TrialRow, VerdictRow

__all__ = ["Database", "is_locked_error"]

T = TypeVar("T")


def is_locked_error(exc: BaseException) -> bool:
    """True for SQLite lock/busy errors (retryable)."""
    return isinstance(exc, OperationalError) and ("locked" in str(exc).lower() or "busy" in str(exc).lower())


class Database:
    """Results database.

    Args:
        path: SQLite file (``:memory:`` supported).
        lock_retries: attempts when SQLite reports the database is locked.
    """

    def __init__(self, path: str | Path, *, lock_retries: int = 6) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        url = "sqlite://" if self.path == ":memory:" else f"sqlite:///{self.path}"
        self.engine = create_engine(url, connect_args={"timeout": 5, "check_same_thread": False})
        self.lock_retries = lock_retries
        try:
            SQLModel.metadata.create_all(self.engine)
        except OperationalError as exc:
            raise StorageError(f"cannot open database {self.path}: {exc}") from exc

    def _with_retry(self, fn: Callable[[], T]) -> T:
        wrapped = retry(
            retry=retry_if_exception(is_locked_error),
            stop=stop_after_attempt(self.lock_retries),
            wait=backoff(0.05, 1.0),
            reraise=True,
        )(fn)
        try:
            return wrapped()
        except OperationalError as exc:
            raise StorageError(f"database error: {exc}") from exc

    # ------------------------------------------------------------------ writes
    def start_run(self, row: RunRow) -> None:
        """Insert the run row at the beginning of a run."""

        def op() -> None:
            with Session(self.engine) as session:
                session.merge(row)
                session.commit()

        self._with_retry(op)

    def save_trials(self, items: list[tuple[Trial, list[Verdict]]]) -> None:
        """Persist trials and their verdicts in one transaction."""

        def op() -> None:
            with Session(self.engine) as session:
                for trial, verdicts in items:
                    session.merge(
                        TrialRow(
                            id=trial.trial_id,
                            run_id=trial.run_id,
                            case_id=trial.case_id,
                            trial_index=trial.trial_index,
                            mutation_id=trial.mutation_id,
                            seed=trial.seed,
                            violated=trial.violated,
                            inconclusive=trial.inconclusive,
                            objective_met=trial.objective_met,
                            error_type=trial.error.type if trial.error else None,
                            error_message=trial.error.message if trial.error else None,
                            started_at=trial.started_at,
                            ended_at=trial.ended_at,
                        )
                    )
                    for verdict in verdicts:
                        session.add(
                            VerdictRow(
                                run_id=trial.run_id,
                                trial_id=trial.trial_id,
                                detector_id=verdict.detector_id,
                                violated=verdict.violated,
                                confidence=verdict.confidence,
                                explanation=verdict.explanation,
                                evidence_json=json.dumps([e.model_dump() for e in verdict.evidence]),
                            )
                        )
                session.commit()

        self._with_retry(op)

    def save_judge_call(self, row: JudgeCallRow) -> None:
        """Persist a raw judge call."""

        def op() -> None:
            with Session(self.engine) as session:
                session.add(row)
                session.commit()

        self._with_retry(op)

    def finish_run(self, result: RunResult) -> None:
        """Store the final ``RunResult`` and per-case rows."""

        def op() -> None:
            with Session(self.engine) as session:
                row = session.get(RunRow, result.run_id) or RunRow(
                    id=result.run_id, name=result.name, started_at=result.started_at
                )
                row.ended_at = result.ended_at
                row.status = "partial" if result.partial else "completed"
                row.partial = result.partial
                row.risk_score = result.risk_score
                row.grade = result.grade
                row.target_type = result.target.type
                row.target_name = result.target.name
                row.config_hash = result.config_hash
                row.result_json = result.model_dump_json()
                session.add(row)
                for case in result.cases:
                    session.add(
                        CaseRow(
                            run_id=result.run_id,
                            case_id=case.case_id,
                            category=case.category.value,
                            status=case.status.value,
                            n_trials=case.n_trials,
                            n_violations=case.n_violations,
                            violation_rate=case.violation_rate,
                            ci_low=case.ci_low,
                            ci_high=case.ci_high,
                        )
                    )
                session.commit()

        self._with_retry(op)

    # ------------------------------------------------------------------ reads
    def list_runs(self, limit: int = 100) -> list[RunRow]:
        """Most recent runs first."""

        def op() -> list[RunRow]:
            with Session(self.engine) as session:
                rows = session.exec(select(RunRow).order_by(col(RunRow.started_at).desc()).limit(limit)).all()
                return list(rows)

        return self._with_retry(op)

    def load_run(self, run_id: str) -> RunResult:
        """Load a finished run's ``RunResult`` (prefix match on the id is allowed).

        Raises:
            StorageError: unknown run or run without results.
        """

        def op() -> RunRow | None:
            with Session(self.engine) as session:
                row = session.get(RunRow, run_id)
                if row is None:
                    rows = session.exec(select(RunRow).where(col(RunRow.id).startswith(run_id))).all()
                    row = rows[0] if len(rows) == 1 else None
                return row

        row = self._with_retry(op)
        if row is None:
            raise StorageError(f"unknown run id {run_id!r}")
        if not row.result_json:
            raise StorageError(f"run {row.id} has no stored results (status: {row.status})")
        return RunResult.model_validate_json(row.result_json)

    def trial_rows(self, run_id: str, case_id: str | None = None) -> list[TrialRow]:
        """Trial rows of a run (optionally one case)."""

        def op() -> list[TrialRow]:
            with Session(self.engine) as session:
                query = select(TrialRow).where(TrialRow.run_id == run_id)
                if case_id:
                    query = query.where(TrialRow.case_id == case_id)
                return list(session.exec(query).all())

        return self._with_retry(op)

    def verdict_rows(self, trial_id: str) -> list[dict[str, Any]]:
        """Verdicts of one trial as dicts."""

        def op() -> list[dict[str, Any]]:
            with Session(self.engine) as session:
                rows = session.exec(select(VerdictRow).where(VerdictRow.trial_id == trial_id)).all()
                return [r.model_dump() for r in rows]

        return self._with_retry(op)

    def judge_calls(self, run_id: str) -> list[JudgeCallRow]:
        """Judge calls of a run."""

        def op() -> list[JudgeCallRow]:
            with Session(self.engine) as session:
                return list(session.exec(select(JudgeCallRow).where(JudgeCallRow.run_id == run_id)).all())

        return self._with_retry(op)
