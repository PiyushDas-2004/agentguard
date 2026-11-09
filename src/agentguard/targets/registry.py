"""Map ``target.type`` to an adapter (built-ins + ``agentguard.targets`` entry points)."""

from __future__ import annotations

from collections.abc import Callable
from importlib.metadata import EntryPoint

from agentguard.config.loader import interpolate_env
from agentguard.config.models import TargetConfig
from agentguard.core.errors import ConfigError
from agentguard.plugins import discover
from agentguard.targets.base import BaseTarget

__all__ = ["BUILTIN_TARGETS", "build_target", "target_types"]


def _python(config: TargetConfig) -> BaseTarget:
    from agentguard.targets.python_callable import PythonCallableTarget

    assert config.path is not None
    return PythonCallableTarget(config.path)


def _http(config: TargetConfig) -> BaseTarget:
    from agentguard.targets.http import HTTPTarget

    target: BaseTarget = HTTPTarget.from_config(config)
    return target


def _openai(config: TargetConfig) -> BaseTarget:
    from agentguard.targets.openai_compat import OpenAICompatibleTarget

    target: BaseTarget = OpenAICompatibleTarget.from_config(config)
    return target


def _langchain(config: TargetConfig) -> BaseTarget:
    from agentguard.targets.langchain import LangChainTarget

    target: BaseTarget = LangChainTarget.from_config(config)
    return target


def _mcp(config: TargetConfig) -> BaseTarget:
    from agentguard.targets.mcp import MCPTarget

    target: BaseTarget = MCPTarget.from_config(config)
    return target


BUILTIN_TARGETS: dict[str, Callable[[TargetConfig], BaseTarget]] = {
    "python_callable": _python,
    "http": _http,
    "openai_compat": _openai,
    "langchain": _langchain,
    "mcp": _mcp,
}


def target_types(extra: list[EntryPoint] | None = None) -> list[str]:
    """All available target types."""
    return sorted(set(BUILTIN_TARGETS) | set(discover("agentguard.targets", extra)))


def build_target(config: TargetConfig, *, extra_plugins: list[EntryPoint] | None = None) -> BaseTarget:
    """Instantiate the adapter for ``config.type``.

    Raises:
        ConfigError: unknown type or adapter construction failure.
    """
    if config.url:
        config = config.model_copy(update={"url": interpolate_env(config.url)})
    factory = BUILTIN_TARGETS.get(config.type)
    if factory is not None:
        return factory(config)
    plugins = discover("agentguard.targets", extra_plugins)
    if config.type in plugins:
        cls = plugins[config.type]
        target = cls(config)
        if not isinstance(target, BaseTarget):
            raise ConfigError(f"plugin target {config.type!r} is not a BaseTarget")
        return target
    raise ConfigError(
        f"target.type: unknown target type {config.type!r} — hint: one of {sorted(set(BUILTIN_TARGETS) | set(plugins))}"
    )
