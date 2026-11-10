"""Database round trips, locked-database retries and the gzipped transcript store."""

from __future__ import annotations

import gzip
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import tenacity
from sqlalchemy.exc import OperationalError

from agentguard.core.errors import StorageError
from agentguard.core.types import (
    AttackCategory,
    CaseResult,
    CaseStatus,
    ErrorInfo,
    EvidenceSpan,
    Role,
    RunResult,
    Severity,
    TargetInfo,
    Transcript,
    TranscriptTurn,
    Trial,
    Verdict,
)
from agentguard.storage import db as db_module
from agentguard.storage.db import Database, is_locked_error
from agentguard.storage.models import JudgeCallRow, RunRow
from agentguard.storage.transcripts import TranscriptStore

T0 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def locked(msg: str = "database is locked") -> OperationalError:
    return OperationalError("UPDATE x", {}, Exception(msg))


def trial(case_id: str = "PI-DIR-001", index: int = 0, run_id: str = "run-abc", **kw: Any) -> Trial:
    return Trial(
        run_id=run_id,
        case_id=case_id,
        trial_index=index,
        seed=42,
        transcript=Transcript(turns=[TranscriptTurn(index=0, role=Role.user, content="hi")]),
        started_at=T0,
        **kw,
    )


def result(run_id: str = "run-abc", **kw: Any) -> RunResult:
    case = CaseResult(
        case_id="PI-DIR-001",
        category=AttackCategory.PI_DIRECT,
        n_trials=2,
        n_errors=0,
        n_violations=1,
        violation_rate=0.5,
        ci_low=0.1,
        ci_high=0.9,
        severity=Severity.high,
        risk_contribution=3.5,
        status=CaseStatus.inconclusive,
    )
    return RunResult(
        run_id=run_id,
        name="demo",
        started_at=T0,
        ended_at=T0,
        target=TargetInfo(type="python_callable", name="agent"),
        config_hash="abcd",
        agentguard_version="1.0.0",
        seed=1,
        trials_per_case=2,
        fail_threshold_risk=40,
        risk_score=12.5,
        grade="B",
        cases=[case],
        **kw,
    )


@pytest.fixture
def database(tmp_path: Path) -> Database:
    return Database(tmp_path / "nested" / "ag.db")


class TestDatabase:
    def test_creates_parent_dir(self, tmp_path: Path) -> None:
        Database(tmp_path / "a" / "b" / "x.db")
        assert (tmp_path / "a" / "b" / "x.db").exists()

    def test_memory_db(self) -> None:
        mem = Database(":memory:")
        mem.start_run(RunRow(id="r", name="n", started_at=T0))
        assert [r.id for r in mem.list_runs()] == ["r"]

    def test_unopenable_path(self, tmp_path: Path) -> None:
        directory = tmp_path / "dir.db"
        directory.mkdir()
        with pytest.raises(StorageError, match="cannot open database"):
            Database(directory)

    def test_round_trip(self, database: Database) -> None:
        database.start_run(RunRow(id="run-abc", name="demo", started_at=T0))
        runs = database.list_runs()
        assert [(r.id, r.status) for r in runs] == [("run-abc", "running")]
        with pytest.raises(StorageError, match="has no stored results"):
            database.load_run("run-abc")

        verdict = Verdict(
            detector_id="canary",
            trial_id="x",
            violated=True,
            confidence=0.9,
            evidence=[EvidenceSpan(turn_index=1, start=0, end=4, text="leak", reason="canary")],
            explanation="leaked",
        )
        failed = trial(index=1, error=ErrorInfo(type="TargetError", message="boom"), violated=None)
        database.save_trials([(trial(violated=True, objective_met=True), [verdict]), (failed, [])])
        rows = database.trial_rows("run-abc")
        assert {r.trial_index for r in rows} == {0, 1}
        by_index = {r.trial_index: r for r in rows}
        assert by_index[0].violated is True and by_index[0].objective_met is True
        assert by_index[1].error_type == "TargetError" and by_index[1].error_message == "boom"
        assert database.trial_rows("run-abc", case_id="OTHER") == []
        assert len(database.trial_rows("run-abc", case_id="PI-DIR-001")) == 2

        verdicts = database.verdict_rows(trial().trial_id)
        assert len(verdicts) == 1
        assert verdicts[0]["detector_id"] == "canary" and verdicts[0]["violated"] is True
        assert '"text": "leak"' in verdicts[0]["evidence_json"]

        database.save_judge_call(
            JudgeCallRow(run_id="run-abc", trial_id="t", judge_id="mock", rubric="jailbreak", raw_output="{}")
        )
        calls = database.judge_calls("run-abc")
        assert [(c.judge_id, c.rubric) for c in calls] == [("mock", "jailbreak")]
        assert database.judge_calls("other") == []

        final = result()
        database.finish_run(final)
        assert database.load_run("run-abc") == final
        (row,) = database.list_runs()
        assert (row.status, row.grade, row.risk_score, row.target_type) == ("completed", "B", 12.5, "python_callable")

    def test_save_trials_is_idempotent_per_trial(self, database: Database) -> None:
        database.save_trials([(trial(violated=False), [])])
        database.save_trials([(trial(violated=True), [])])
        (row,) = database.trial_rows("run-abc")
        assert row.violated is True

    def test_finish_without_start_and_partial(self, database: Database) -> None:
        database.finish_run(result("run-xyz", partial=True, abort_reason="budget"))
        (row,) = database.list_runs()
        assert row.status == "partial" and row.partial
        assert database.load_run("run-xyz").abort_reason == "budget"

    def test_prefix_lookup(self, database: Database) -> None:
        database.finish_run(result("run-aaa111"))
        database.finish_run(result("run-aab222"))
        assert database.load_run("run-aaa").run_id == "run-aaa111"
        with pytest.raises(StorageError, match="unknown run id 'run-aa'"):
            database.load_run("run-aa")  # ambiguous
        with pytest.raises(StorageError, match="unknown run id 'zzz'"):
            database.load_run("zzz")

    def test_list_runs_order_and_limit(self, database: Database) -> None:
        for i in range(3):
            database.start_run(RunRow(id=f"r{i}", name="n", started_at=T0.replace(hour=i)))
        assert [r.id for r in database.list_runs()] == ["r2", "r1", "r0"]
        assert [r.id for r in database.list_runs(limit=1)] == ["r2"]


class FlakySession:
    """Wraps the real Session; the first ``failures`` constructions raise 'database is locked'."""

    failures = 0
    attempts = 0

    def __new__(cls, *args: Any, **kwargs: Any) -> Any:
        cls.attempts += 1
        if cls.attempts <= cls.failures:
            raise locked()
        return REAL_SESSION(*args, **kwargs)


REAL_SESSION = db_module.Session


class TestLockedRetry:
    @pytest.fixture(autouse=True)
    def _flaky(self, monkeypatch: pytest.MonkeyPatch) -> None:
        FlakySession.attempts = 0
        monkeypatch.setattr(db_module, "Session", FlakySession)
        # keep the backoff schedule out of the test's wall time (tenacity is not under test)
        monkeypatch.setattr(db_module, "wait_exponential_jitter", lambda **_: tenacity.wait_none())

    def test_is_locked_error(self) -> None:
        assert is_locked_error(locked())
        assert is_locked_error(locked("database is busy"))
        assert not is_locked_error(locked("no such table"))
        assert not is_locked_error(ValueError("database is locked"))

    def test_recovers_after_transient_locks(self, tmp_path: Path) -> None:
        database = Database(tmp_path / "x.db", lock_retries=5)
        FlakySession.failures = 3
        database.start_run(RunRow(id="r", name="n", started_at=T0))
        assert FlakySession.attempts == 4
        FlakySession.failures = 0
        assert [r.id for r in database.list_runs()] == ["r"]

    def test_gives_up(self, tmp_path: Path) -> None:
        database = Database(tmp_path / "x.db", lock_retries=2)
        FlakySession.failures = 100
        with pytest.raises(StorageError, match="database error: .*database is locked"):
            database.list_runs()
        assert FlakySession.attempts == 2

    def test_non_lock_error_not_retried(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        database = Database(tmp_path / "x.db", lock_retries=5)
        calls = 0

        def boom(*args: Any, **kwargs: Any) -> Any:
            nonlocal calls
            calls += 1
            raise locked("disk I/O error")

        monkeypatch.setattr(db_module, "Session", boom)
        with pytest.raises(StorageError, match="disk I/O error"):
            database.list_runs()
        assert calls == 1


class TestTranscriptStore:
    def test_append_read_get(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path / "t")
        first = [trial(index=0), trial(index=1)]
        store.append(first)
        store.append([trial(index=2, mutation_id="base64")])
        trials = list(store.read("run-abc"))
        assert [t.trial_index for t in trials] == [0, 1, 2]
        assert trials[0] == first[0]
        assert store.get("run-abc", trial(index=2, mutation_id="base64").trial_id) is not None
        assert store.get("run-abc", "missing") is None
        assert store.path("run-abc") == tmp_path / "t" / "run-abc.jsonl.gz"

    def test_empty_inputs(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path / "t")
        store.append([])
        assert not (tmp_path / "t").exists()
        assert list(store.read("nope")) == []

    def test_blank_lines_ignored(self, tmp_path: Path) -> None:
        store = TranscriptStore(tmp_path)
        with gzip.open(store.path("r"), "wt", encoding="utf-8") as handle:
            handle.write("\n" + trial(run_id="r").model_dump_json() + "\n\n")
        assert len(list(store.read("r"))) == 1

    def test_write_failure(self, tmp_path: Path) -> None:
        blocker = tmp_path / "file"
        blocker.write_text("x")
        with pytest.raises(StorageError, match="cannot write transcripts"):
            TranscriptStore(blocker / "sub").append([trial()])
