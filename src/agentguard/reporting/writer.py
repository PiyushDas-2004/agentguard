"""Write report files to disk with clear errors (e.g. disk full)."""

from __future__ import annotations

import errno
import os
import tempfile
from collections.abc import Callable, Iterable
from pathlib import Path

from agentguard.core.errors import ReportWriteError
from agentguard.core.types import RunResult
from agentguard.reporting.html import render_html
from agentguard.reporting.json_report import render_json
from agentguard.reporting.junit import render_junit
from agentguard.reporting.markdown import render_markdown
from agentguard.reporting.sarif import render_sarif

__all__ = ["EXTENSIONS", "RENDERERS", "write_report", "write_reports"]

RENDERERS: dict[str, Callable[[RunResult], str]] = {
    "html": render_html,
    "json": render_json,
    "sarif": render_sarif,
    "junit": render_junit,
    "markdown": render_markdown,
}
EXTENSIONS = {"html": "html", "json": "json", "sarif": "sarif", "junit": "junit.xml", "markdown": "md"}


def write_report(result: RunResult, fmt: str, out_dir: str | Path) -> Path:
    """Render ``fmt`` and write it atomically to ``out_dir/<run_id>.<ext>``.

    Raises:
        ReportWriteError: on any filesystem error, with a disk-full specific hint.
    """
    if fmt not in RENDERERS:
        raise ReportWriteError(f"unknown report format {fmt!r}; choose from {sorted(RENDERERS)}")
    directory = Path(out_dir)
    content = RENDERERS[fmt](result)
    target = directory / f"agentguard-{result.run_id}.{EXTENSIONS[fmt]}"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".part")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
            os.chmod(tmp, 0o644)  # reports are meant to be world-readable
            os.replace(tmp, target)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
    except OSError as exc:
        hint = " (disk full — free space or choose another reports.out_dir)" if exc.errno == errno.ENOSPC else ""
        raise ReportWriteError(f"cannot write {fmt} report to {target}: {exc.strerror or exc}{hint}") from exc
    return target


def write_reports(result: RunResult, formats: Iterable[str], out_dir: str | Path) -> dict[str, Path]:
    """Write every requested format; returns ``{format: path}``."""
    return {fmt: write_report(result, fmt, out_dir) for fmt in formats}
