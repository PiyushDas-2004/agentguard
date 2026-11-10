"""Bad datasets, Ctrl-C, giant output and non-UTF-8 output are handled gracefully."""

from __future__ import annotations

import asyncio
import signal

import pytest
from typer.testing import CliRunner

from agentguard.cli import app
from agentguard.core.errors import DatasetError
from agentguard.core.runner import RunOptions
from agentguard.core.types import Role
from agentguard.reporting.html import render_html
from agentguard.reporting.json_report import render_json
from agentguard.reporting.markdown import render_markdown
from agentguard.storage.db import Database
from agentguard.storage.transcripts import TranscriptStore
from agentguard.targets.python_callable import load_object
from tests.failure_injection._support import case, make_config, make_runner, run
from tests.failure_injection.test_storage_and_reports import _write_cli_config

INVALID = case("FI-BAD-001", severity="catastrophic")  # not a valid severity


def _cases_with_one_invalid():
    return [case("FI-OK-001"), INVALID, case("FI-OK-002")]


# ------------------------------------------------------------------ invalid dataset case
def test_invalid_case_is_skipped_with_warning(tmp_path):
    config = make_config(tmp_path, _cases_with_one_invalid())
    result = run(make_runner(config, lambda message: "fine"))
    assert sorted(c.case_id for c in result.cases) == ["FI-OK-001", "FI-OK-002"]
    warning = next(w for w in result.warnings if "FI-BAD-001" in w)
    assert "skipped invalid case" in warning
    assert "severity" in warning


def test_invalid_case_is_an_error_in_strict_mode(tmp_path):
    config = make_config(tmp_path, _cases_with_one_invalid())
    runner = make_runner(config, lambda message: "fine", options=RunOptions(offline=True, strict=True))
    with pytest.raises(DatasetError, match="FI-BAD-001"):
        run(runner)


def test_strict_datasets_from_config(tmp_path):
    config = make_config(tmp_path, _cases_with_one_invalid(), run={"strict_datasets": True})
    with pytest.raises(DatasetError):
        run(make_runner(config, lambda message: "fine"))


def test_cli_strict_invalid_dataset_exits_with_config_error(tmp_path):
    config_file = _write_cli_config(tmp_path, cases=_cases_with_one_invalid())
    outcome = CliRunner().invoke(app, ["run", "-c", str(config_file), "--offline", "--quiet", "--strict"])
    assert outcome.exit_code == 2, outcome.output
    assert "FI-BAD-001" in outcome.output


def test_cli_non_strict_invalid_dataset_runs(tmp_path):
    config_file = _write_cli_config(tmp_path, cases=_cases_with_one_invalid())
    outcome = CliRunner().invoke(
        app, ["run", "-c", str(config_file), "--offline", "--quiet", "--fail-threshold", "100"]
    )
    assert outcome.exit_code == 0, outcome.output
    assert "skipped invalid case FI-BAD-001" in outcome.output


# ------------------------------------------------------------------ KeyboardInterrupt
def _six_cases():
    return [case(f"FI-INT-{i:03d}") for i in range(1, 7)]


def test_keyboard_interrupt_preserves_partial_results(tmp_path):
    calls = 0

    async def interrupting(conversation, tools, context):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise KeyboardInterrupt
        return "Leak: " + context.system_prompt

    config = make_config(tmp_path, _six_cases())
    runner = make_runner(config, interrupting)
    with pytest.raises(KeyboardInterrupt):
        asyncio.run(runner.run())

    result = runner.result
    assert result is not None, "runner.result must hold the partial result after Ctrl-C"
    assert result.partial is True
    assert result.abort_reason == "interrupted"
    assert result.total_trials == 2
    assert sorted(c.case_id for c in result.cases) == ["FI-INT-001", "FI-INT-002"]
    assert "PARTIAL" in render_markdown(result)
    assert "PARTIAL (interrupted)" in render_html(result)
    stored = Database(tmp_path / "agentguard.db").load_run(result.run_id)
    assert stored.partial is True
    assert len(list(TranscriptStore(tmp_path / "transcripts").read(result.run_id))) == 2


def test_sigint_cancels_cleanly_and_returns_partial_result(tmp_path):
    calls = 0

    async def ctrl_c(conversation, tools, context):
        nonlocal calls
        calls += 1
        if calls == 3:
            signal.raise_signal(signal.SIGINT)
            await asyncio.sleep(1)
        return "fine"

    config = make_config(tmp_path, _six_cases())
    runner = make_runner(config, ctrl_c)
    try:
        returned = asyncio.run(runner.run())
    except KeyboardInterrupt:
        returned = None
    result = runner.result
    assert result is not None
    assert returned is None or returned is result
    assert result.partial
    assert result.abort_reason == "interrupted"
    assert result.total_trials == 2


def test_cli_interrupt_writes_partial_reports(tmp_path):
    load_object("tests/failure_injection/agents.py:interrupting_agent").calls = 0
    config_file = _write_cli_config(tmp_path, agent="interrupting_agent", cases=_six_cases())
    outcome = CliRunner().invoke(app, ["run", "-c", str(config_file), "--offline", "--quiet"])
    assert outcome.exit_code == 3, outcome.output
    assert "PARTIAL" in outcome.output
    reports = tmp_path / "reports"
    markdown = next(reports.glob("*.md")).read_text(encoding="utf-8")
    assert "PARTIAL" in markdown
    assert "PARTIAL (interrupted)" in next(reports.glob("*.html")).read_text(encoding="utf-8")
    assert len(list(reports.iterdir())) == 5


# ------------------------------------------------------------------ giant output
def test_giant_output_is_truncated_and_flagged_by_resource_detector(tmp_path):
    giant = "A" * 300_000

    async def flood(conversation, tools, context):
        return giant

    config = make_config(
        tmp_path,
        [case("FI-BIG-001", category="DENIAL_OF_WALLET", detectors=["resource"])],
        run={"max_output_chars": 50_000},
    )
    result = run(make_runner(config, flood))
    sample = result.cases[0].samples[0]
    reply = next(t for t in sample.transcript.turns if t.role == Role.assistant)
    assert len(reply.content) == 50_000
    assert reply.truncated is True
    assert sample.transcript.metadata["original_output_chars"] == 300_000
    assert sample.transcript.metadata["output_truncated"] is True
    assert sample.violated is True
    (verdict,) = [v for v in sample.verdicts if v.detector_id == "resource"]
    assert verdict.violated
    assert any("300000 chars" in e.reason for e in verdict.evidence)
    # Reports render the (already truncated) transcript without choking.
    assert "truncated in report" in render_html(result)


# ------------------------------------------------------------------ non-UTF-8 output
def test_non_utf8_bytes_become_replacement_chars_and_store_fine(tmp_path):
    async def binary(conversation, tools, context):
        return b"caf\xe9 \xff\xfe bytes \x00 end"

    async def surrogate(conversation, tools, context):
        return {"text": "lone surrogate \udcff and NUL \x00 here"}

    for name, agent in (("bin", binary), ("sur", surrogate)):
        sub = tmp_path / name
        config = make_config(sub, [case("FI-ENC-001")])
        result = run(make_runner(config, agent))
        assert result.total_errors == 0
        reply = result.cases[0].samples[0].transcript.turns[-1].content
        assert "\x00" not in reply
        reply.encode("utf-8")  # must be valid UTF-8
        if name == "bin":
            assert "�" in reply
            assert reply.startswith("caf�")
        else:
            assert "\udcff" not in reply
        stored = list(TranscriptStore(sub / "transcripts").read(result.run_id))
        assert stored[0].transcript.turns[-1].content == reply
        assert Database(sub / "agentguard.db").load_run(result.run_id).cases[0].case_id == "FI-ENC-001"
        render_json(result).encode("utf-8")
        render_html(result).encode("utf-8")
