"""``agentguard`` command-line interface."""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import platform
import sys
from importlib import resources
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

from agentguard.config.loader import load_config
from agentguard.core.errors import AgentGuardError, ConfigError, DatasetError, ExitCode, ReportWriteError, StorageError
from agentguard.core.types import AttackCategory, CaseStatus, RunResult, Severity
from agentguard.version import __version__

__all__ = ["app", "exit_code_for", "main"]

app = typer.Typer(
    name="agentguard",
    help="Security & quality evaluation framework for AI agents.\n\n"
    "Example: agentguard run -c examples/demo.yaml --offline",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="markdown",
)
console = Console(stderr=False)
err_console = Console(stderr=True)


def _fail(message: str, code: ExitCode) -> typer.Exit:
    err_console.print(f"[bold red]error:[/] {message}")
    return typer.Exit(int(code))


def exit_code_for(result: RunResult) -> ExitCode:
    """Map a run result to the CLI exit code (budget > threshold/critical > ok)."""
    if result.partial and result.abort_reason == "budget":
        return ExitCode.BUDGET_EXCEEDED
    if result.partial:
        return ExitCode.RUNTIME_ERROR
    critical_failure = any(
        c.status == CaseStatus.failed and c.severity == Severity.critical for c in result.security_cases()
    )
    if not result.passed_threshold or critical_failure:
        return ExitCode.RISK_ABOVE_THRESHOLD
    return ExitCode.OK


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"agentguard {__version__}")
        raise typer.Exit(0)


@app.callback()
def _root(
    version: Annotated[
        bool, typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version and exit.")
    ] = False,
) -> None:
    """AgentGuard command group."""


# ---------------------------------------------------------------------------------------------- init
@app.command()
def init(
    directory: Annotated[Path, typer.Option("--dir", help="Where to write the files.")] = Path("."),
    force: Annotated[bool, typer.Option(help="Overwrite existing files.")] = False,
) -> None:
    """Scaffold `agentguard.yaml` and `policy.yaml` in the current directory.

    Example: `agentguard init && agentguard run -c agentguard.yaml --offline`
    """
    files = {"agentguard.yaml": "init_config.yaml", "policy.yaml": "policy_template.yaml"}
    directory.mkdir(parents=True, exist_ok=True)
    for name, template in files.items():
        target = directory / name
        if target.exists() and not force:
            err_console.print(f"[yellow]skipped[/] {target} (exists; use --force)")
            continue
        target.write_text(resources.files("agentguard.data").joinpath(template).read_text(encoding="utf-8"))
        console.print(f"[green]wrote[/] {target}")


# ---------------------------------------------------------------------------------------------- doctor
EXTRAS = {
    "litellm": "litellm",
    "ragas": "ragas",
    "deepeval": "deepeval",
    "presidio": "presidio_analyzer",
    "dashboard": "fastapi",
    "langchain": "langchain_core",
    "mcp": "mcp",
    "otel": "opentelemetry.sdk",
}


@app.command()
def doctor() -> None:
    """Check Python, optional extras, API keys and write permissions."""
    table = Table(title="agentguard doctor")
    table.add_column("check")
    table.add_column("status")
    table.add_column("detail")
    ok = sys.version_info >= (3, 11)
    table.add_row("python", "ok" if ok else "FAIL", f"{platform.python_version()} (need >= 3.11)")
    for extra, module in EXTRAS.items():
        try:
            importlib.import_module(module)
            table.add_row(f"extra [{extra}]", "ok", "installed")
        except ImportError:
            table.add_row(f"extra [{extra}]", "missing", f"pip install 'agentguard[{extra}]'")
    for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        table.add_row(key, "set" if os.environ.get(key) else "unset", "needed only for live providers")
    for path in (Path("reports"), Path(".agentguard")):
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".write-test"
            probe.write_text("ok")
            probe.unlink()
            table.add_row(f"write {path}/", "ok", str(path.resolve()))
        except OSError as exc:
            ok = False
            table.add_row(f"write {path}/", "FAIL", str(exc))
    datasets = Path("datasets/attacks")
    table.add_row("datasets", "ok" if datasets.exists() else "missing", str(datasets.resolve()))
    console.print(table)
    if not ok:
        raise typer.Exit(int(ExitCode.RUNTIME_ERROR))


# ---------------------------------------------------------------------------------------------- run
def _write(result: RunResult, formats: list[str], out_dir: str) -> dict[str, Path]:
    from agentguard.reporting.writer import write_reports

    return write_reports(result, formats, out_dir)


def _summary(result: RunResult, paths: dict[str, Path]) -> None:
    table = Table(title=f"AgentGuard — {result.name}{' (PARTIAL)' if result.partial else ''}")
    for col in ("category", "cases", "fail", "pass", "inconcl.", "violation rate (95% CI)"):
        table.add_column(col)
    for card in result.categories:
        table.add_row(
            card.category.value,
            str(card.n_cases),
            str(card.n_fail),
            str(card.n_pass),
            str(card.n_inconclusive),
            f"{card.violation_rate:.0%} ({card.ci_low:.2f}–{card.ci_high:.2f})",
        )
    console.print(table)
    status = "[green]PASSED[/]" if result.passed_threshold else "[red]FAILED[/]"
    console.print(
        f"Risk score [bold]{result.risk_score:.1f}[/] / 100 · grade [bold]{result.grade}[/] · threshold "
        f"{result.fail_threshold_risk:g} → {status}"
    )
    if result.over_refusal_rate is not None:
        console.print(f"Over-refusal rate: {result.over_refusal_rate:.1%}")
    if result.quality and result.quality.task_success_rate is not None:
        console.print(f"Quality: task success {result.quality.task_success_rate:.0%} · RAG {result.quality.rag}")
    console.print(
        f"Trials: {result.total_trials} ({result.total_errors} errors) · cost ${result.total_cost_usd:.4f} · "
        f"{result.duration_s:.1f}s · run id {result.run_id}"
    )
    for fmt, path in paths.items():
        console.print(f"  {fmt:<9} {path}")


@app.command()
def run(
    config: Annotated[Path, typer.Option("-c", "--config", help="Path to the YAML config.")],
    suite: Annotated[str, typer.Option(help="security | quality | all")] = "all",
    category: Annotated[list[AttackCategory] | None, typer.Option(help="Only these categories (repeatable).")] = None,
    case: Annotated[list[str] | None, typer.Option(help="Only these case ids (repeatable).")] = None,
    trials: Annotated[int | None, typer.Option(min=1, help="Override run.trials_per_case.")] = None,
    offline: Annotated[bool, typer.Option(help="Force deterministic mock models (no network LLM calls).")] = False,
    max_cost: Annotated[float | None, typer.Option(min=0, help="Hard budget cap in USD.")] = None,
    fail_threshold: Annotated[float | None, typer.Option(min=0, max=100, help="Risk score that fails CI.")] = None,
    strict: Annotated[bool, typer.Option(help="Fail on any invalid dataset case.")] = False,
    out_dir: Annotated[str | None, typer.Option(help="Override reports.out_dir.")] = None,
    quiet: Annotated[bool, typer.Option(help="No progress bar.")] = False,
) -> None:
    """Run the security and/or quality suites against a target.

    Exit codes: 0 passed · 1 risk above threshold or critical failure · 2 config error ·
    3 runtime error · 4 budget exceeded (partial results are saved and reported).

    Example: `agentguard run -c examples/demo.yaml --offline --category PI_DIRECT --trials 3`
    """
    from agentguard.core.runner import RunOptions, Runner

    if suite not in {"security", "quality", "all"}:
        raise _fail(f"--suite must be security, quality or all (got {suite!r})", ExitCode.CONFIG_ERROR)
    try:
        cfg = load_config(config)
    except ConfigError as exc:
        raise _fail(exc.message, ExitCode.CONFIG_ERROR) from exc
    progress = Progress(
        TextColumn("[bold]trials"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
        disable=quiet,
    )
    task_id = progress.add_task("trials", total=None)

    def on_progress(done: int, total: int) -> None:
        progress.update(task_id, completed=done, total=total)

    options = RunOptions(
        suite=suite,
        categories=category or None,
        case_ids=case or None,
        trials=trials,
        offline=offline,
        max_cost_usd=max_cost,
        fail_threshold=fail_threshold,
        strict=strict or None,
        progress=on_progress,
    )
    runner = Runner(cfg, options, base_dir=config.resolve().parent)
    interrupted = False
    try:
        with progress:
            result = asyncio.run(runner.run())
    except KeyboardInterrupt:
        interrupted = True
        if runner.result is None:
            raise _fail("interrupted before any results were produced", ExitCode.RUNTIME_ERROR) from None
        result = runner.result
    except (ConfigError, DatasetError) as exc:
        raise _fail(exc.message, ExitCode.CONFIG_ERROR) from exc
    except AgentGuardError as exc:
        raise _fail(exc.message, ExitCode.RUNTIME_ERROR) from exc
    if interrupted and not result.partial:
        result = result.model_copy(update={"partial": True, "abort_reason": "interrupted"})
    try:
        paths = _write(result, list(cfg.reports.formats), out_dir or str(runner._path(cfg.reports.out_dir)))
    except ReportWriteError as exc:
        _summary(result, {})
        raise _fail(exc.message, ExitCode.RUNTIME_ERROR) from exc
    _summary(result, paths)
    for warning in result.warnings[:5]:
        err_console.print(f"[yellow]warning:[/] {warning.splitlines()[0][:200]}")
    raise typer.Exit(int(exit_code_for(result)))


# ---------------------------------------------------------------------------------------------- report/compare
def _db(db_path: str) -> object:
    from agentguard.storage.db import Database

    return Database(db_path)


@app.command()
def report(
    run_id: Annotated[str, typer.Argument(help="Run id (prefix allowed).")],
    fmt: Annotated[list[str], typer.Option("--format", "-f", help="html|json|sarif|junit|markdown (repeatable)")],
    out_dir: Annotated[str, typer.Option(help="Output directory.")] = "reports/",
    db_path: Annotated[str, typer.Option(help="Results database.")] = ".agentguard/agentguard.db",
) -> None:
    """Regenerate reports for a stored run.

    Example: `agentguard report 20261109-120000-abc123 --format html --format sarif`
    """
    from agentguard.storage.db import Database

    try:
        result = Database(db_path).load_run(run_id)
        paths = _write(result, fmt, out_dir)
    except (StorageError, ReportWriteError) as exc:
        raise _fail(exc.message, ExitCode.RUNTIME_ERROR) from exc
    for name, path in paths.items():
        console.print(f"{name:<9} {path}")


@app.command()
def compare(
    run_a: Annotated[str, typer.Argument(help="Baseline run id.")],
    run_b: Annotated[str, typer.Argument(help="Candidate run id.")],
    db_path: Annotated[str, typer.Option(help="Results database.")] = ".agentguard/agentguard.db",
    as_json: Annotated[bool, typer.Option("--json", help="Print JSON.")] = False,
) -> None:
    """Compare two runs: new failures, fixed cases, risk delta, significant category deltas.

    Example: `agentguard compare RUN_A RUN_B`
    """
    from agentguard.scoring.compare import compare_runs
    from agentguard.storage.db import Database

    try:
        db = Database(db_path)
        comparison = compare_runs(db.load_run(run_a), db.load_run(run_b))
    except StorageError as exc:
        raise _fail(exc.message, ExitCode.RUNTIME_ERROR) from exc
    if as_json:
        console.print_json(comparison.model_dump_json())
        return
    console.print(
        f"Risk {comparison.risk_a:.1f} ({comparison.grade_a}) → {comparison.risk_b:.1f} "
        f"({comparison.grade_b}) · Δ {comparison.risk_delta:+.1f}"
    )
    console.print(f"New failures ({len(comparison.new_failures)}): {', '.join(comparison.new_failures) or '—'}")
    console.print(f"Fixed ({len(comparison.fixed)}): {', '.join(comparison.fixed) or '—'}")
    table = Table(title="Category deltas")
    for col in ("category", "rate A", "rate B", "Δ", "significant"):
        table.add_column(col)
    for cat in comparison.categories:
        table.add_row(
            cat.category,
            f"{cat.rate_a:.0%}",
            f"{cat.rate_b:.0%}",
            f"{cat.delta:+.0%}",
            "yes" if cat.significant else "no",
        )
    console.print(table)


# ---------------------------------------------------------------------------------------------- datasets
@app.command("list-attacks")
def list_attacks(
    category: Annotated[AttackCategory | None, typer.Option(help="Filter by category.")] = None,
    severity: Annotated[Severity | None, typer.Option(help="Filter by severity.")] = None,
    datasets: Annotated[list[Path] | None, typer.Option(help="Dataset dirs/files.")] = None,
) -> None:
    """List attack and benign cases.

    Example: `agentguard list-attacks --category PI_INDIRECT --severity critical`
    """
    from agentguard.attacks.loader import load_cases, select_cases

    paths = datasets or [Path("datasets/attacks"), Path("datasets/benign")]
    try:
        loaded = load_cases([p for p in paths if p.exists()])
    except DatasetError as exc:
        raise _fail(exc.message, ExitCode.CONFIG_ERROR) from exc
    cases = select_cases(
        loaded.cases, categories=[category] if category else None, severities=[severity.value] if severity else None
    )
    table = Table(title=f"{len(cases)} cases")
    for col in ("id", "category", "severity", "vector", "title"):
        table.add_column(col)
    for c in cases:
        table.add_row(c.id, c.category.value, c.severity.value, c.vector.value, c.title)
    console.print(table)


@app.command("lint-datasets")
def lint_datasets(
    root: Annotated[Path, typer.Option(help="Datasets root directory.")] = Path("datasets"),
    no_minimums: Annotated[bool, typer.Option(help="Do not enforce per-category minimum counts.")] = False,
) -> None:
    """Validate datasets: schema, unique ids, OWASP/ATLAS ids, near-duplicates, detectors, counts."""
    from agentguard.attacks.lint import lint_all

    report_ = lint_all(root, enforce_minimums=not no_minimums)
    table = Table(title="dataset counts")
    table.add_column("dataset")
    table.add_column("count", justify="right")
    for key, value in report_.counts.items():
        table.add_row(key, str(value))
    console.print(table)
    for warning in report_.warnings:
        err_console.print(f"[yellow]warning:[/] {warning}")
    for error in report_.errors:
        err_console.print(f"[red]error:[/] {error}")
    if not report_.ok:
        raise typer.Exit(1)
    console.print("[green]datasets OK[/]")


# ---------------------------------------------------------------------------------------------- judge
@app.command("calibrate-judge")
def calibrate_judge(
    judge: Annotated[str, typer.Option(help="mock | anthropic | openai")] = "mock",
    model: Annotated[str | None, typer.Option(help="Model id for live judges.")] = None,
    gold: Annotated[Path, typer.Option(help="Gold set JSONL.")] = Path("datasets/judge_gold/gold_set.jsonl"),
    out: Annotated[Path | None, typer.Option(help="Write the report as JSON.")] = None,
) -> None:
    """Measure judge agreement with the hand-labelled gold set (accuracy, P/R/F1, Cohen's kappa).

    Example: `agentguard calibrate-judge --judge mock`
    """
    from agentguard.config.models import JudgeConfig
    from agentguard.core.runner import build_judge
    from agentguard.judges.calibration import calibrate, load_gold_set

    if judge not in {"mock", "anthropic", "openai"}:
        raise _fail("--judge must be mock, anthropic or openai", ExitCode.CONFIG_ERROR)
    try:
        examples = load_gold_set(gold)
        judge_impl = build_judge(JudgeConfig(provider=judge, model=model), offline=False)  # type: ignore[arg-type]
    except (DatasetError, ConfigError) as exc:
        raise _fail(exc.message, ExitCode.CONFIG_ERROR) from exc
    result = asyncio.run(calibrate(judge_impl, examples))
    table = Table(title=f"judge calibration ({result.judge_id}, n={result.overall.n})")
    for col in ("scope", "n", "accuracy", "precision", "recall", "F1", "kappa", "TP", "FP", "TN", "FN"):
        table.add_column(col)
    rows = [("overall", result.overall), *result.per_rubric.items()]
    for name, m in rows:
        table.add_row(
            name,
            str(m.n),
            f"{m.accuracy:.3f}",
            f"{m.precision:.3f}",
            f"{m.recall:.3f}",
            f"{m.f1:.3f}",
            f"{m.kappa:.3f}",
            str(m.tp),
            str(m.fp),
            str(m.tn),
            str(m.fn),
        )
    console.print(table)
    console.print(
        f"Confusion matrix (rows = gold, cols = judge): [[TN {result.overall.tn}, FP {result.overall.fp}], "
        f"[FN {result.overall.fn}, TP {result.overall.tp}]]"
    )
    if out:
        out.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    if not result.meets_target:
        msg = f"kappa {result.overall.kappa:.3f} is below the {result.kappa_target:.2f} target"
        if judge == "mock":
            err_console.print(f"[yellow]note:[/] {msg} (offline rule-based MockJudge; reported honestly)")
        else:
            err_console.print(f"[yellow]warning:[/] {msg} — do not trust this judge for gating decisions")


# ---------------------------------------------------------------------------------------------- meta-validation
@app.command("meta-validate")
def meta_validate(
    ground_truth: Annotated[Path, typer.Option(help="Ground-truth YAML.")] = Path("examples/ground_truth.yaml"),
    config: Annotated[Path, typer.Option("-c", "--config", help="Base config.")] = Path("examples/demo.yaml"),
    trials: Annotated[int | None, typer.Option(min=1, help="Override trials per case.")] = None,
    out: Annotated[Path | None, typer.Option(help="Write results JSON.")] = None,
) -> None:
    """Run the security suite against every demo agent and score AgentGuard itself vs. ground truth.

    Example: `agentguard meta-validate --out docs/meta_validation.json`
    """
    from agentguard.metavalidate import render_table, run_meta_validation

    try:
        cfg = load_config(config)
        result = asyncio.run(
            run_meta_validation(
                cfg, ground_truth, trials=trials, base_dir=Path.cwd(), progress=lambda m: console.print(m, style="dim")
            )
        )
    except (ConfigError, DatasetError) as exc:
        raise _fail(exc.message, ExitCode.CONFIG_ERROR) from exc
    console.print(render_table(result))
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result.model_dump(mode="json"), indent=2), encoding="utf-8")
    if not result.targets_met:
        err_console.print("[red]meta-validation targets NOT met[/]")
        raise typer.Exit(1)
    console.print("[green]meta-validation targets met[/]")


# ---------------------------------------------------------------------------------------------- dashboard
@app.command()
def dashboard(
    port: Annotated[int, typer.Option(help="Port to listen on.")] = 8000,
    host: Annotated[str, typer.Option(help="Interface to bind.")] = "127.0.0.1",
    db_path: Annotated[str, typer.Option(help="Results database.")] = ".agentguard/agentguard.db",
) -> None:
    """Serve the results dashboard (FastAPI + HTMX).

    Example: `agentguard dashboard --port 8000`
    """
    try:
        import uvicorn

        from agentguard.dashboard.app import create_app
    except ImportError as exc:
        raise _fail("the dashboard needs: pip install 'agentguard[dashboard]'", ExitCode.CONFIG_ERROR) from exc
    uvicorn.run(create_app(db_path), host=host, port=port, log_level="info")


def main() -> None:
    """Console-script entry point."""
    app()
