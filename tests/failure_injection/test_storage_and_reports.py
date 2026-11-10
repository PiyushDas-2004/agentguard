"""Locked SQLite and a full disk produce retries / clear errors instead of crashes."""

from __future__ import annotations

import errno
import io
import os
import sqlite3
import threading
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from typer.testing import CliRunner

from agentguard.cli import app
from agentguard.core.errors import ReportWriteError, StorageError
from agentguard.core.types import Trial
from agentguard.reporting import writer as writer_module
from agentguard.reporting.writer import write_report, write_reports
from agentguard.storage.db import Database
from tests.failure_injection._support import case, make_config, make_runner, run


def _short_timeout(db: Database) -> Database:
    """Make SQLite give up on a lock quickly so the retry layer is exercised."""
    db.engine = create_engine(f"sqlite:///{db.path}", connect_args={"timeout": 0.05, "check_same_thread": False})
    return db


def _hold_lock(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=0.05, check_same_thread=False)
    conn.execute("BEGIN EXCLUSIVE")
    return conn


def test_locked_sqlite_is_retried_until_the_lock_is_released(tmp_path):
    db = _short_timeout(Database(tmp_path / "locked.db", lock_retries=8))
    holder = _hold_lock(db.path)
    timer = threading.Timer(0.3, holder.rollback)
    timer.start()
    try:
        trial = Trial(run_id="r1", case_id="FI-TST-001", trial_index=0, seed=1)
        db.save_trials([(trial, [])])  # first attempts hit "database is locked"
    finally:
        timer.join()
        holder.close()
    assert [r.case_id for r in db.trial_rows("r1")] == ["FI-TST-001"]


def test_persistently_locked_sqlite_raises_storage_error(tmp_path):
    db = _short_timeout(Database(tmp_path / "locked.db", lock_retries=2))
    holder = _hold_lock(db.path)
    try:
        with pytest.raises(StorageError, match="locked"):
            db.save_trials([(Trial(run_id="r1", case_id="FI-TST-001", trial_index=0, seed=1), [])])
    finally:
        holder.rollback()
        holder.close()


def test_run_survives_a_temporarily_locked_database(tmp_path):
    config = make_config(tmp_path, [case("FI-TST-001"), case("FI-TST-002")])
    db = _short_timeout(Database(tmp_path / "agentguard.db", lock_retries=8))
    holder = _hold_lock(db.path)
    timer = threading.Timer(0.3, holder.rollback)
    timer.start()
    try:
        runner = make_runner(config, lambda message: "fine")
        runner._database = db
        result = run(runner)
    finally:
        timer.join()
        holder.close()
    assert not result.partial
    assert db.load_run(result.run_id).total_trials == 2


class _FullDisk(io.StringIO):
    def write(self, s: str) -> int:
        raise OSError(errno.ENOSPC, "No space left on device")


def _fill_disk(monkeypatch: pytest.MonkeyPatch) -> None:
    def fdopen(fd, *args, **kwargs):
        os.close(fd)
        return _FullDisk()

    monkeypatch.setattr(writer_module.os, "fdopen", fdopen)


@pytest.fixture
def small_result(tmp_path):
    config = make_config(tmp_path, [case("FI-TST-001")])
    return run(make_runner(config, lambda message: "fine"))


@pytest.mark.parametrize("fmt", ["html", "json", "sarif", "junit", "markdown"])
def test_disk_full_raises_report_write_error(tmp_path, monkeypatch, small_result, fmt):
    _fill_disk(monkeypatch)
    out = tmp_path / "out"
    with pytest.raises(ReportWriteError, match="disk full") as info:
        write_report(small_result, fmt, out)
    assert "No space left on device" in info.value.message
    assert list(out.iterdir()) == [], "no partial or temporary file may be left behind"


def test_other_os_errors_have_no_disk_full_hint(tmp_path, small_result):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    with pytest.raises(ReportWriteError) as info:
        write_report(small_result, "json", blocker / "sub")
    assert "disk full" not in info.value.message


def test_unknown_report_format(tmp_path, small_result):
    with pytest.raises(ReportWriteError, match="unknown report format"):
        write_reports(small_result, ["pdf"], tmp_path)


def test_cli_reports_disk_full_with_runtime_error_exit(tmp_path, monkeypatch):
    config_file = _write_cli_config(tmp_path)
    _fill_disk(monkeypatch)
    outcome = CliRunner().invoke(app, ["run", "-c", str(config_file), "--offline", "--quiet"])
    assert outcome.exit_code == 3, outcome.output
    assert "disk full" in outcome.output


def _write_cli_config(tmp_path: Path, agent: str = "echo_agent", cases: list[dict] | None = None) -> Path:
    import yaml

    from tests.failure_injection._support import POLICY, write_dataset

    datasets = write_dataset(tmp_path / "datasets", cases or [case("FI-CLI-001")])
    data = {
        "version": 1,
        "run": {"name": "cli-fi", "trials_per_case": 1, "concurrency": 1, "seed": 3},
        "target": {"type": "python_callable", "path": f"tests/failure_injection/agents.py:{agent}"},
        "policy": POLICY,
        "suites": {"security": {"datasets": [str(datasets)]}},
        "reports": {"out_dir": str(tmp_path / "reports")},
        "storage": {"db_path": str(tmp_path / "ag.db"), "transcripts_dir": str(tmp_path / "tr")},
    }
    path = tmp_path / "agentguard.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path
