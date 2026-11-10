"""Target registry: built-in types, unknown types, and plugin targets from entry points."""

from __future__ import annotations

from importlib.metadata import EntryPoint

import pytest

from agentguard.config.models import TargetConfig
from agentguard.core.errors import ConfigError
from agentguard.harness.sandbox import ToolSandbox
from agentguard.llm.base import LLMMessage
from agentguard.targets.base import BaseTarget, TargetContext, TargetResponse
from agentguard.targets.http import HTTPTarget
from agentguard.targets.openai_compat import OpenAICompatibleTarget
from agentguard.targets.python_callable import PythonCallableTarget
from agentguard.targets.registry import BUILTIN_TARGETS, build_target, target_types


class EchoTarget(BaseTarget):
    """Minimal plugin target used through an injected entry point."""

    type_name = "echo"

    def __init__(self, config: TargetConfig) -> None:
        self.prefix = str(config.options.get("prefix", ""))

    async def send(self, conversation: list[LLMMessage], tools: ToolSandbox, context: TargetContext) -> TargetResponse:
        return TargetResponse(text=self.prefix + conversation[-1].content)


ECHO_EP = EntryPoint("echo", "tests.integration.targets.test_registry:EchoTarget", "agentguard.targets")


@pytest.mark.parametrize(
    ("config", "cls"),
    [
        (TargetConfig(type="python_callable", path="examples/targets/vulnerable_agent.py:agent"), PythonCallableTarget),
        (TargetConfig(type="http", url="http://127.0.0.1:8765/chat"), HTTPTarget),
        (TargetConfig(type="openai_compat", url="http://127.0.0.1:8000/v1", model="m"), OpenAICompatibleTarget),
    ],
)
def test_builtin_types(config: TargetConfig, cls: type[BaseTarget]) -> None:
    target = build_target(config)
    assert isinstance(target, cls)
    assert target.type_name == config.type


def test_optional_builtin_types() -> None:
    pytest.importorskip("langchain_core")
    pytest.importorskip("mcp")
    from agentguard.targets.langchain import LangChainTarget
    from agentguard.targets.mcp import MCPTarget

    lc = build_target(TargetConfig(type="langchain", path="langchain_core.runnables:RunnablePassthrough"))
    assert isinstance(lc, LangChainTarget)
    mcp = build_target(TargetConfig(type="mcp", command="python", args=["examples/targets/mcp_demo_server.py"]))
    assert isinstance(mcp, MCPTarget)


def test_target_types_lists_builtins_and_plugins() -> None:
    assert set(BUILTIN_TARGETS) <= set(target_types())
    assert target_types() == sorted(target_types())
    assert "echo" in target_types([ECHO_EP])
    assert "echo" not in target_types()


def test_unknown_type_has_hint() -> None:
    with pytest.raises(ConfigError) as info:
        build_target(TargetConfig(type="grpc"))
    message = str(info.value)
    assert message.startswith("target.type: unknown target type 'grpc'")
    assert "hint: one of" in message
    for name in BUILTIN_TARGETS:
        assert name in message


def test_unknown_type_hint_includes_plugins() -> None:
    with pytest.raises(ConfigError, match="'echo'"):
        build_target(TargetConfig(type="grpc"), extra_plugins=[ECHO_EP])


async def test_plugin_target_from_entry_point(sandbox: ToolSandbox, context: TargetContext) -> None:
    target = build_target(TargetConfig(type="echo", options={"prefix": "> "}), extra_plugins=[ECHO_EP])
    assert isinstance(target, EchoTarget)
    assert target.name == "echo"
    assert target.describe() == {}
    await target.start()
    response = await target.send([LLMMessage(role="user", content="ping")], sandbox, context)
    await target.aclose()
    assert response.text == "> ping"


def test_builtin_wins_over_plugin_with_same_name() -> None:
    shadow = EntryPoint("http", "tests.integration.targets.test_registry:EchoTarget", "agentguard.targets")
    target = build_target(TargetConfig(type="http", url="http://127.0.0.1:1/x"), extra_plugins=[shadow])
    assert isinstance(target, HTTPTarget)


def test_url_env_interpolation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AG_REG_BASE", "http://127.0.0.1:4321")
    target = build_target(TargetConfig(type="openai_compat", url="${AG_REG_BASE}/v1", model="m"))
    assert isinstance(target, OpenAICompatibleTarget)
    assert target.url == "http://127.0.0.1:4321/v1/chat/completions"
