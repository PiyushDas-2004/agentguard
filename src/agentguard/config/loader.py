"""Load and validate YAML configuration with path-specific, actionable error messages."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from agentguard.config.models import AgentGuardConfig
from agentguard.core.errors import ConfigError

__all__ = [
    "config_hash",
    "format_validation_error",
    "interpolate_env",
    "load_config",
    "resolve_path",
]

_HINTS: dict[str, str] = {
    "greater_than_equal": "use a value >= {ge}",
    "greater_than": "use a value > {gt}",
    "less_than_equal": "use a value <= {le}",
    "less_than": "use a value < {lt}",
    "literal_error": "allowed values: {expected}",
    "extra_forbidden": "remove this key or check its spelling",
    "missing": "add this required key",
    "int_parsing": "use an integer",
    "float_parsing": "use a number",
    "bool_parsing": "use true or false",
    "enum": "allowed values: {expected}",
    "string_type": "use a string",
    "list_type": "use a YAML list",
    "dict_type": "use a YAML mapping",
}

_MESSAGES: dict[str, str] = {
    "greater_than_equal": "must be >= {ge}",
    "greater_than": "must be > {gt}",
    "less_than_equal": "must be <= {le}",
    "less_than": "must be < {lt}",
    "missing": "is required",
    "extra_forbidden": "is not a recognised key",
}


def _loc_to_path(loc: tuple[int | str, ...]) -> str:
    path = ""
    for part in loc:
        if isinstance(part, int):
            path += f"[{part}]"
        elif part in {"function-after", "function-before"} or str(part).startswith(("literal[", "list[")):
            continue
        else:
            path += ("." if path else "") + str(part)
    return path


def format_validation_error(exc: ValidationError, *, prefix: str = "", origin: str = "config") -> str:
    """Turn a Pydantic ``ValidationError`` into ``path: message (got X) — hint`` lines.

    Example output: ``suites.security.mutations.per_case: must be >= 0 (got -1) — hint: use a
    value >= 0``.
    """
    lines: list[str] = []
    for error in exc.errors():
        path = _loc_to_path(tuple(error["loc"]))
        if prefix:
            path = f"{prefix}.{path}" if path else prefix
        ctx = {k: v for k, v in (error.get("ctx") or {}).items()}
        etype = error["type"]
        template = _MESSAGES.get(etype)
        message = template.format(**ctx) if template else error["msg"].removeprefix("Value error, ")
        line = f"{path or '<root>'}: {message}"
        if etype not in {"missing"} and "input" in error and not isinstance(error["input"], dict):
            line += f" (got {error['input']!r})"
        hint = _HINTS.get(etype)
        if hint:
            try:
                line += " — hint: " + hint.format(**ctx)
            except KeyError:
                line += " — hint: " + hint.split("{", 1)[0].strip()  # context value unavailable
        lines.append(line)
    header = f"invalid configuration in {origin}:"
    return header + "\n  " + "\n  ".join(lines)


_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def interpolate_env(value: str, *, strict: bool = False) -> str:
    """Replace ``${VAR}`` / ``${VAR:-default}`` with environment values.

    Raises:
        ConfigError: if ``strict`` and a variable without default is unset.
    """

    def repl(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        if name in os.environ:
            return os.environ[name]
        if default is not None:
            return default
        if strict:
            raise ConfigError(f"environment variable {name} is not set (referenced as ${{{name}}})")
        return ""

    return _ENV_RE.sub(repl, value)


def resolve_path(value: str, base_dir: Path) -> Path:
    """Resolve a path: absolute, then CWD-relative, then config-dir-relative, then bundled datasets."""
    path = Path(value)
    if path.is_absolute():
        return path
    if path.exists():
        return path.resolve()
    candidate = base_dir / path
    if candidate.exists():
        return candidate.resolve()
    from agentguard.bundled import resolve_bundled

    return resolve_bundled(path) or path


def load_config(path: str | Path) -> AgentGuardConfig:
    """Load a YAML config file into an :class:`AgentGuardConfig`.

    Raises:
        ConfigError: for missing files, YAML syntax errors, or schema violations; messages name
            the exact YAML path and give a fix hint.
    """
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigError(f"config file not found: {config_path} (hint: run 'agentguard init')")
    try:
        raw = config_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"cannot read config {config_path}: {exc}") from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise ConfigError(f"invalid YAML in {config_path}{where}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{config_path}: top level must be a mapping (got {type(data).__name__})")
    return parse_config(data, origin=str(config_path))


def parse_config(data: dict[str, Any], *, origin: str = "config") -> AgentGuardConfig:
    """Validate an already-parsed mapping (see :func:`load_config`)."""
    try:
        return AgentGuardConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(format_validation_error(exc, origin=origin)) from exc


def config_hash(config: AgentGuardConfig) -> str:
    """Stable SHA-256 (first 16 hex chars) of the normalized configuration."""
    payload = json.dumps(config.model_dump(mode="json"), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
