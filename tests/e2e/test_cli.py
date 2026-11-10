"""End-to-end tests of the ``agentguard`` CLI with typer's CliRunner (offline, temp storage)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

import agentguard.cli as cli_module
from agentguard.cli import app, exit_code_for
from agentguard.config.loader import load_config
from agentguard.core.errors import ExitCode
from agentguard.storage.db import Database
from agentguard.version import __version__

ROOT = Path(__file__).resolve().parents[2]
COMMANDS = [
    "init",
    "doctor",
    "run",
    "report",
    "compare",
    "list-attacks",
    "lint-datasets",
    "calibrate-judge",
    "meta-validate",
    "dashboard",
]


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> CliRunner:
    # wide consoles so rich does not wrap paths and ids
    monkeypatch.setattr(cli_module.console, "width", 250)
    monkeypatch.setattr(cli_module.err_console, "width", 250)
    return CliRunner()


def write_config(
    tmp_path: Path,
    agent: str = "vulnerable_agent.py:agent",
    *,
    name: str = "cli-test",
    categories: list[str] | None = None,
    cases: list[str] | None = None,
    formats: list[str] | None = None,
    filename: str = "agentguard.yaml",
    **run: Any,
) -> Path:
    security: dict[str, Any] = {
        "categories": categories or ["SYS_PROMPT_LEAK"],
        "datasets": [str(ROOT / "datasets" / "attacks"), str(ROOT / "datasets" / "benign")],
    }
    if cases:
        security["cases"] = cases
    data = {
        "version": 1,
        "run": {"name": name, "trials_per_case": 2, "seed": 1337, **run},
        "target": {"type": "python_callable", "path": str(ROOT / "examples" / "targets" / agent)},
        "policy": str(ROOT / "examples" / "policy.yaml"),
        "suites": {"security": security},
        "reports": {"formats": formats or ["json"], "out_dir": str(tmp_path / "reports")},
        "storage": {"db_path": str(tmp_path / "ag.db"), "transcripts_dir": str(tmp_path / "transcripts")},
    }
    path = tmp_path / filename
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def run_ids(tmp_path: Path) -> list[str]:
    """Run ids in the temp database, oldest first."""
    return [r.id for r in reversed(Database(tmp_path / "ag.db").list_runs())]


# ---------------------------------------------------------------------------------------------- basics
def test_version(runner: CliRunner) -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"agentguard {__version__}"


def test_no_args_shows_help(runner: CliRunner) -> None:
    result = runner.invoke(app, [])
    assert result.exit_code in (0, 2)
    assert "Usage" in result.output
    for command in COMMANDS:
        assert command in result.output


@pytest.mark.parametrize("command", COMMANDS)
def test_command_help(runner: CliRunner, command: str) -> None:
    result = runner.invoke(app, [command, "--help"])
    assert result.exit_code == 0, result.output
    assert "Usage" in result.output
    assert command in result.output


def test_main_entry_point(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "argv", ["agentguard", "--version"])
    with pytest.raises(SystemExit) as info:
        cli_module.main()
    assert info.value.code == 0
    assert __version__ in capsys.readouterr().out


# ---------------------------------------------------------------------------------------------- init / doctor
def test_init_and_force(runner: CliRunner, tmp_path: Path) -> None:
    target = tmp_path / "project"
    result = runner.invoke(app, ["init", "--dir", str(target)])
    assert result.exit_code == 0, result.output
    assert "wrote" in result.output
    config = load_config(target / "agentguard.yaml")
    assert config.target.type == "python_callable"
    assert (target / "policy.yaml").read_text().strip()

    (target / "agentguard.yaml").write_text("# my edits\n")
    again = runner.invoke(app, ["init", "--dir", str(target)])
    assert again.exit_code == 0
    assert "skipped" in again.output and "--force" in again.output
    assert (target / "agentguard.yaml").read_text() == "# my edits\n"

    forced = runner.invoke(app, ["init", "--dir", str(target), "--force"])
    assert forced.exit_code == 0
    assert "my edits" not in (target / "agentguard.yaml").read_text()
    load_config(target / "agentguard.yaml")


def test_doctor(runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "agentguard doctor" in out
    assert "python" in out
    assert "extra [dashboard]" in out
    assert "ANTHROPIC_API_KEY" in out and "set" in out
    assert "write reports/" in out
    assert (tmp_path / "reports").is_dir() and (tmp_path / ".agentguard").is_dir()
    assert not (tmp_path / "reports" / ".write-test").exists()


def test_doctor_reports_missing_extra_and_unwritable_dir(
    runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "reports").write_text("a file where a directory should be")
    monkeypatch.setitem(sys.modules, "ragas", None)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == int(ExitCode.RUNTIME_ERROR)
    assert "FAIL" in result.output
    assert "pip install 'agentguard[ragas]'" in result.output


# ---------------------------------------------------------------------------------------------- run
def test_run_vulnerable_exits_1(runner: CliRunner, tmp_path: Path) -> None:
    config = write_config(tmp_path, formats=["json", "html"])
    result = runner.invoke(app, ["run", "-c", str(config), "--offline", "--quiet"])
    assert result.exit_code == int(ExitCode.RISK_ABOVE_THRESHOLD), result.output
    assert "FAILED" in result.output
    assert "SYS_PROMPT_LEAK" in result.output
    reports = sorted(p.suffix for p in (tmp_path / "reports").iterdir())
    assert reports == [".html", ".json"]
    payload = json.loads(next((tmp_path / "reports").glob("*.json")).read_text())
    assert payload["risk_score"] > 40
    assert len(run_ids(tmp_path)) == 1


def test_run_hardened_subset_exits_0(runner: CliRunner, tmp_path: Path) -> None:
    config = write_config(tmp_path, "hardened_agent.py:agent", categories=["SYS_PROMPT_LEAK", "PI_DIRECT"])
    out_dir = tmp_path / "custom-out"
    result = runner.invoke(
        app,
        [
            "run",
            "-c",
            str(config),
            "--offline",
            "--case",
            "SPL-001",
            "--case",
            "PI-DIR-001",
            "--category",
            "SYS_PROMPT_LEAK",
            "--category",
            "PI_DIRECT",
            "--trials",
            "2",
            "--fail-threshold",
            "99",
            "--suite",
            "security",
            "--out-dir",
            str(out_dir),
            "--strict",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "PASSED" in result.output
    assert "Trials: 4 (0 errors)" in result.output
    assert len(list(out_dir.glob("*.json"))) == 1


def test_run_bad_config_exits_2_with_path(runner: CliRunner, tmp_path: Path) -> None:
    config = write_config(tmp_path)
    data = yaml.safe_load(config.read_text())
    data["run"]["trials_per_case"] = 0
    config.write_text(yaml.safe_dump(data))
    result = runner.invoke(app, ["run", "-c", str(config), "--offline"])
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
    assert "run.trials_per_case" in result.output
    assert "error:" in result.output


def test_run_missing_config_and_bad_suite(runner: CliRunner, tmp_path: Path) -> None:
    missing = runner.invoke(app, ["run", "-c", str(tmp_path / "nope.yaml")])
    assert missing.exit_code == int(ExitCode.CONFIG_ERROR)
    assert "nope.yaml" in missing.output
    suite = runner.invoke(app, ["run", "-c", str(write_config(tmp_path)), "--suite", "everything"])
    assert suite.exit_code == int(ExitCode.CONFIG_ERROR)
    assert "--suite must be security, quality or all" in suite.output


def test_run_no_cases_selected_exits_2(runner: CliRunner, tmp_path: Path) -> None:
    config = write_config(tmp_path)
    result = runner.invoke(app, ["run", "-c", str(config), "--offline", "--case", "NOPE-999"])
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
    assert "no attack cases selected" in result.output


def test_run_budget_exceeded_exits_4(runner: CliRunner, tmp_path: Path) -> None:
    config = write_config(tmp_path)
    result = runner.invoke(app, ["run", "-c", str(config), "--offline", "--quiet", "--max-cost", "0.000001"])
    assert result.exit_code == int(ExitCode.BUDGET_EXCEEDED), result.output
    assert "PARTIAL" in result.output
    payload = json.loads(next((tmp_path / "reports").glob("*.json")).read_text())
    assert payload["partial"] is True
    assert payload["abort_reason"] == "budget"


def test_run_report_write_failure_exits_3(runner: CliRunner, tmp_path: Path) -> None:
    config = write_config(tmp_path)
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    result = runner.invoke(
        app, ["run", "-c", str(config), "--offline", "--quiet", "--case", "SPL-001", "--out-dir", str(blocker / "x")]
    )
    assert result.exit_code == int(ExitCode.RUNTIME_ERROR)
    assert "error:" in result.output
    assert "Risk score" in result.output  # the summary is still printed


def test_run_warnings_are_printed(runner: CliRunner, tmp_path: Path) -> None:
    broken = tmp_path / "broken_pack.yaml"
    broken.write_text("pack: broken\ncases:\n  - id: not-valid\n")
    config = write_config(tmp_path)
    data = yaml.safe_load(config.read_text())
    data["suites"]["security"]["datasets"].append(str(broken))
    config.write_text(yaml.safe_dump(data))
    result = runner.invoke(app, ["run", "-c", str(config), "--offline", "--quiet", "--case", "SPL-001"])
    assert result.exit_code == int(ExitCode.RISK_ABOVE_THRESHOLD)
    assert "warning:" in result.output
    strict = runner.invoke(app, ["run", "-c", str(config), "--offline", "--quiet", "--strict"])
    assert strict.exit_code == int(ExitCode.CONFIG_ERROR)
    assert "broken_pack.yaml" in strict.output


# ---------------------------------------------------------------------------------------------- report / compare
@pytest.fixture
def two_runs(runner: CliRunner, tmp_path: Path) -> tuple[Path, str, str]:
    vulnerable = write_config(tmp_path, name="vuln", filename="a.yaml")
    hardened = write_config(tmp_path, "hardened_agent.py:agent", name="hard", filename="b.yaml")
    args = ["--offline", "--quiet", "--case", "SPL-001", "--case", "SPL-002", "--trials", "2"]
    assert runner.invoke(app, ["run", "-c", str(vulnerable), *args]).exit_code == 1
    assert runner.invoke(app, ["run", "-c", str(hardened), *args, "--fail-threshold", "99"]).exit_code == 0
    first, second = run_ids(tmp_path)
    return tmp_path / "ag.db", first, second


def test_report_regeneration(runner: CliRunner, tmp_path: Path, two_runs: tuple[Path, str, str]) -> None:
    db, first, _ = two_runs
    out = tmp_path / "regen"
    result = runner.invoke(
        app,
        ["report", first[:-1], "-f", "html", "--format", "sarif", "-f", "junit", "-f", "markdown", "--out-dir", str(out), "--db-path", str(db)],
    )
    assert result.exit_code == 0, result.output
    suffixes = sorted(p.name.split(".", 1)[1] for p in out.iterdir())
    assert suffixes == ["html", "md", "sarif", "xml"]
    sarif = json.loads(next(out.glob("*.sarif*")).read_text())
    assert sarif["version"] == "2.1.0"
    for name in ("html", "sarif", "junit", "markdown"):
        assert name in result.output


def test_report_unknown_run_exits_3(runner: CliRunner, tmp_path: Path) -> None:
    result = runner.invoke(app, ["report", "nope", "-f", "json", "--db-path", str(tmp_path / "ag.db")])
    assert result.exit_code == int(ExitCode.RUNTIME_ERROR)
    assert "nope" in result.output


def test_compare_text_and_json(runner: CliRunner, two_runs: tuple[Path, str, str]) -> None:
    db, first, second = two_runs
    text = runner.invoke(app, ["compare", first, second, "--db-path", str(db)])
    assert text.exit_code == 0, text.output
    assert "Risk " in text.output and "→" in text.output
    assert "Fixed (" in text.output
    assert "SYS_PROMPT_LEAK" in text.output

    as_json = runner.invoke(app, ["compare", first, second, "--db-path", str(db), "--json"])
    assert as_json.exit_code == 0
    data = json.loads(as_json.output)
    assert data["risk_a"] > data["risk_b"]
    assert data["risk_delta"] == pytest.approx(data["risk_b"] - data["risk_a"])
    assert set(data["fixed"]) <= {"SPL-001", "SPL-002"}
    assert data["new_failures"] == []


def test_compare_unknown_run_exits_3(runner: CliRunner, two_runs: tuple[Path, str, str]) -> None:
    db, first, _ = two_runs
    result = runner.invoke(app, ["compare", first, "missing-run", "--db-path", str(db)])
    assert result.exit_code == int(ExitCode.RUNTIME_ERROR)
    assert "missing-run" in result.output


# ---------------------------------------------------------------------------------------------- datasets
def test_list_attacks_filters(runner: CliRunner) -> None:
    everything = runner.invoke(app, ["list-attacks"])
    assert everything.exit_code == 0
    total = int(everything.output.split(" cases")[0].split()[-1])

    filtered = runner.invoke(app, ["list-attacks", "--category", "PI_INDIRECT", "--severity", "critical"])
    assert filtered.exit_code == 0
    count = int(filtered.output.split(" cases")[0].split()[-1])
    assert 0 < count < total
    body = filtered.output.split("\n", 2)[2]
    assert "PI-IND-" in body
    assert "SPL-" not in body
    assert "high " not in body

    benign = runner.invoke(app, ["list-attacks", "--datasets", "datasets/benign", "--category", "OVER_REFUSAL"])
    assert benign.exit_code == 0
    assert "BEN-001" in benign.output


def test_list_attacks_custom_dataset(runner: CliRunner, tmp_path: Path) -> None:
    pack = ROOT / "examples" / "plugins" / "agentguard_example_plugins" / "packs" / "support_desk.yaml"
    result = runner.invoke(app, ["list-attacks", "--datasets", str(pack), "--datasets", str(tmp_path / "missing")])
    assert result.exit_code == 0
    assert "4 cases" in result.output
    assert "EXA-SD-001" in result.output


def test_lint_datasets(runner: CliRunner, tmp_path: Path) -> None:
    ok = runner.invoke(app, ["lint-datasets"])
    assert ok.exit_code == 0, ok.output
    assert "datasets OK" in ok.output
    assert "dataset counts" in ok.output

    root = tmp_path / "datasets"
    (root / "attacks").mkdir(parents=True)
    (root / "attacks" / "bad.yaml").write_text(
        yaml.safe_dump(
            {
                "pack": "bad",
                "cases": [
                    {
                        "id": "SPL-900",
                        "category": "SYS_PROMPT_LEAK",
                        "title": "Unknown detector case",
                        "description": "A case that references a detector that does not exist.",
                        "severity": "low",
                        "owasp_llm": ["LLM07:2025"],
                        "vector": "user_message",
                        "turns": [{"content": "hello"}],
                        "objective": {"type": "answered", "description": "anything"},
                        "detectors": ["does_not_exist"],
                    }
                ],
            }
        )
    )
    bad = runner.invoke(app, ["lint-datasets", "--root", str(root), "--no-minimums"])
    assert bad.exit_code == 1
    assert "unknown detector 'does_not_exist'" in bad.output
    assert "datasets OK" not in bad.output


# ---------------------------------------------------------------------------------------------- judge
def test_calibrate_judge_mock(runner: CliRunner, tmp_path: Path) -> None:
    out = tmp_path / "calibration.json"
    result = runner.invoke(app, ["calibrate-judge", "--judge", "mock", "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert "judge calibration (mock" in result.output
    assert "Confusion matrix" in result.output
    data = json.loads(out.read_text())
    assert data["judge_id"] == "mock"
    assert data["overall"]["n"] > 0
    assert set(data["per_rubric"]) <= {"jailbreak", "task_success", "faithfulness", "refusal"}
    if not data["meets_target"]:
        assert "reported honestly" in result.output


def test_calibrate_judge_errors(runner: CliRunner, tmp_path: Path) -> None:
    bad_judge = runner.invoke(app, ["calibrate-judge", "--judge", "gpt-judge"])
    assert bad_judge.exit_code == int(ExitCode.CONFIG_ERROR)
    assert "--judge must be mock, anthropic or openai" in bad_judge.output
    missing = runner.invoke(app, ["calibrate-judge", "--gold", str(tmp_path / "missing.jsonl")])
    assert missing.exit_code == int(ExitCode.CONFIG_ERROR)
    assert "missing.jsonl" in missing.output


def test_calibrate_judge_live_below_target_warns(runner: CliRunner, tmp_path: Path) -> None:
    gold_lines = (ROOT / "datasets" / "judge_gold" / "gold_set.jsonl").read_text().splitlines()
    gold = tmp_path / "gold.jsonl"
    # flip every label so any judge is maximally wrong
    flipped = []
    for line in gold_lines:
        if not line.strip():
            continue
        row = json.loads(line)
        row["label"] = not row["label"]
        flipped.append(json.dumps(row))
    gold.write_text("\n".join(flipped) + "\n")
    result = runner.invoke(app, ["calibrate-judge", "--judge", "mock", "--gold", str(gold)])
    assert result.exit_code == 0, result.output
    assert "below the" in result.output


# ---------------------------------------------------------------------------------------------- meta-validation
def _ground_truth(tmp_path: Path, partially_vulnerable: bool) -> Path:
    path = tmp_path / "ground_truth.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "agents": {
                    "vulnerable": {
                        "target": "examples/targets/vulnerable_agent.py:agent",
                        "categories": {"SYS_PROMPT_LEAK": {"vulnerable": True, "why": "no output filter"}},
                    },
                    "partially_hardened": {
                        "target": "examples/targets/partially_hardened_agent.py:agent",
                        "categories": {
                            "SYS_PROMPT_LEAK": {"vulnerable": partially_vulnerable, "why": "literal-phrase filter"}
                        },
                    },
                },
            }
        )
    )
    return path


def test_meta_validate_targets_met(runner: CliRunner, tmp_path: Path) -> None:
    config = write_config(tmp_path, cases=["SPL-001", "SPL-002", "SPL-003"])
    out = tmp_path / "out" / "meta.json"
    result = runner.invoke(
        app,
        [
            "meta-validate",
            "--ground-truth",
            str(_ground_truth(tmp_path, partially_vulnerable=True)),
            "-c",
            str(config),
            "--trials",
            "1",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "meta-validation targets met" in result.output
    assert "AgentGuard meta-validation" in result.output
    data = json.loads(out.read_text())
    assert {(p["agent"], p["category"]) for p in data["pairs"]} == {
        ("vulnerable", "SYS_PROMPT_LEAK"),
        ("partially_hardened", "SYS_PROMPT_LEAK"),
    }
    assert all(p["predicted"] for p in data["pairs"])
    assert data["partial_match_rate"] == 1.0


def test_meta_validate_targets_not_met(runner: CliRunner, tmp_path: Path) -> None:
    config = write_config(tmp_path, cases=["SPL-001", "SPL-002"])
    result = runner.invoke(
        app,
        [
            "meta-validate",
            "--ground-truth",
            str(_ground_truth(tmp_path, partially_vulnerable=False)),
            "-c",
            str(config),
            "--trials",
            "1",
        ],
    )
    assert result.exit_code == 1
    assert "targets NOT met" in result.output


def test_meta_validate_missing_ground_truth(runner: CliRunner, tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["meta-validate", "--ground-truth", str(tmp_path / "gt.yaml"), "-c", str(write_config(tmp_path))]
    )
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
    assert "ground truth not found" in result.output


# ---------------------------------------------------------------------------------------------- dashboard
def test_dashboard_serves_app(runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn

    served: dict[str, Any] = {}

    def fake_run(app_: Any, **kwargs: Any) -> None:  # the network server is the external boundary
        served["app"] = app_
        served.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    db = tmp_path / "dash.db"
    result = runner.invoke(app, ["dashboard", "--port", "8123", "--host", "127.0.0.1", "--db-path", str(db)])
    assert result.exit_code == 0, result.output
    assert (served["host"], served["port"]) == ("127.0.0.1", 8123)
    from fastapi.testclient import TestClient

    assert TestClient(served["app"]).get("/healthz").json()["status"] == "ok"
    assert db.exists()


def test_dashboard_missing_extra(runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "uvicorn", None)
    result = runner.invoke(app, ["dashboard"])
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
    assert "agentguard[dashboard]" in result.output


def test_exit_code_for_mapping(two_runs: tuple[Path, str, str]) -> None:
    db, first, second = two_runs
    vulnerable = Database(db).load_run(first)
    hardened = Database(db).load_run(second)
    assert exit_code_for(vulnerable) == ExitCode.RISK_ABOVE_THRESHOLD
    assert exit_code_for(hardened) == ExitCode.OK
    budget = hardened.model_copy(update={"partial": True, "abort_reason": "budget"})
    assert exit_code_for(budget) == ExitCode.BUDGET_EXCEEDED
    interrupted = hardened.model_copy(update={"partial": True, "abort_reason": "interrupted"})
    assert exit_code_for(interrupted) == ExitCode.RUNTIME_ERROR
