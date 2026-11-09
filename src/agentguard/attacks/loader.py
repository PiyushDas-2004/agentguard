"""Load attack and benign cases from YAML dataset files."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import ValidationError

from agentguard.attacks.models import AttackPack
from agentguard.config.loader import format_validation_error
from agentguard.core.errors import DatasetError
from agentguard.core.types import AttackCase, AttackCategory

__all__ = ["DatasetLoadResult", "load_cases", "select_cases"]

logger = logging.getLogger(__name__)


@dataclass
class DatasetLoadResult:
    """Cases loaded from datasets plus non-fatal problems encountered."""

    cases: list[AttackCase] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    files: list[Path] = field(default_factory=list)


def _iter_files(paths: Iterable[str | Path]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files.extend(sorted(p for p in path.rglob("*.y*ml") if p.is_file()))
        elif path.is_file():
            files.append(path)
        else:
            raise DatasetError(f"dataset path not found: {raw}")
    return files


def load_cases(paths: Iterable[str | Path], *, strict: bool = False) -> DatasetLoadResult:
    """Load every case from the given files/directories.

    Invalid cases are skipped with a warning (or raise :class:`DatasetError` when ``strict``).
    Duplicate case ids are always an error in strict mode and keep the first occurrence otherwise.
    """
    result = DatasetLoadResult()
    seen: dict[str, Path] = {}
    for file in _iter_files(paths):
        result.files.append(file)
        try:
            data = yaml.safe_load(file.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError) as exc:
            message = f"{file}: invalid YAML: {exc}"
            if strict:
                raise DatasetError(message) from exc
            result.warnings.append(message)
            continue
        try:
            pack = AttackPack.model_validate(data)
        except ValidationError as exc:
            message = format_validation_error(exc, origin=str(file))
            if strict:
                raise DatasetError(message) from exc
            result.warnings.append(message)
            continue
        for index, raw_case in enumerate(pack.cases):
            try:
                case = AttackCase.model_validate(raw_case)
            except ValidationError as exc:
                ident = raw_case.get("id", f"#{index}") if isinstance(raw_case, dict) else f"#{index}"
                message = format_validation_error(exc, prefix=f"cases[{index}]", origin=f"{file} ({ident})")
                if strict:
                    raise DatasetError(message) from exc
                logger.warning("skipping invalid case: %s", message)
                result.warnings.append(f"skipped invalid case {ident}: {message}")
                continue
            if case.id in seen:
                message = f"duplicate case id {case.id} in {file} (first defined in {seen[case.id]})"
                if strict:
                    raise DatasetError(message)
                result.warnings.append(message)
                continue
            seen[case.id] = file
            result.cases.append(case)
    return result


def select_cases(
    cases: list[AttackCase],
    *,
    categories: Iterable[AttackCategory] | None = None,
    case_ids: Iterable[str] | None = None,
    severities: Iterable[str] | None = None,
) -> list[AttackCase]:
    """Filter cases by category, id and severity (``None`` means no filter)."""
    selected = cases
    if categories is not None:
        wanted = set(categories)
        selected = [c for c in selected if c.category in wanted]
    if case_ids:
        ids = set(case_ids)
        selected = [c for c in selected if c.id in ids]
    if severities:
        sev = set(severities)
        selected = [c for c in selected if c.severity.value in sev]
    return selected
