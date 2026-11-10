"""LangChainTarget: Runnable and factory forms with sandboxed StructuredTools."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("langchain_core")

from langchain_core.messages import AIMessage, HumanMessage  # noqa: E402
from langchain_core.runnables import RunnableLambda  # noqa: E402
from langchain_core.tools import StructuredTool  # noqa: E402

import agentguard.targets.langchain as lc_module  # noqa: E402
from agentguard.config.models import TargetConfig  # noqa: E402
from agentguard.core.errors import ConfigError, TargetError  # noqa: E402
from agentguard.harness.sandbox import ToolSandbox  # noqa: E402
from agentguard.llm.base import LLMMessage  # noqa: E402
from agentguard.targets.base import TargetContext  # noqa: E402
from agentguard.targets.langchain import LangChainTarget, _text_of, langchain_available, sandbox_tools  # noqa: E402
from agentguard.targets.registry import build_target  # noqa: E402

CONVERSATION = [
    LLMMessage(role="user", content="hello"),
    LLMMessage(role="assistant", content="hi"),
    LLMMessage(role="user", content="summarize the readme"),
]


def test_langchain_available() -> None:
    assert langchain_available() is True


async def test_runnable_form_receives_payload(sandbox: ToolSandbox, context: TargetContext) -> None:
    seen: list[dict[str, Any]] = []

    def respond(payload: dict[str, Any]) -> AIMessage:
        seen.append(payload)
        return AIMessage(content=f"you said: {payload['input']}")

    target = LangChainTarget("inline:runnable", obj=RunnableLambda(respond))
    response = await target.send(CONVERSATION, sandbox, context)
    assert response.text == "you said: summarize the readme"
    assert seen[0]["messages"] == [{"role": m.role, "content": m.content} for m in CONVERSATION]
    assert seen[0]["system_prompt"] == context.system_prompt
    assert target.name == "inline:runnable"
    assert target.describe() == {"path": "inline:runnable"}


async def test_factory_form_gets_sandbox_tools_and_llm(sandbox: ToolSandbox, context: TargetContext) -> None:
    received: dict[str, Any] = {}

    def build(tools: list[Any], llm: Any) -> Any:
        received["tools"] = tools
        received["llm"] = llm
        by_name = {t.name: t for t in tools}

        async def run(payload: dict[str, Any]) -> dict[str, Any]:
            public = await by_name["file_read"].ainvoke({"path": "/sandbox/public/readme.txt"})
            await by_name["file_read"].ainvoke({"path": "/sandbox/private/secrets.txt"})
            await by_name["email_read"].ainvoke({})
            return {"output": AIMessage(content=f"readme: {public[:20]}")}

        return RunnableLambda(run)

    target = LangChainTarget("inline:factory", obj=build)
    response = await target.send(CONVERSATION, sandbox, context)
    assert response.text.startswith("readme: ")
    tools = received["tools"]
    assert all(isinstance(t, StructuredTool) for t in tools)
    assert sorted(t.name for t in tools) == sorted(sandbox.names)
    assert received["llm"] is context.llm
    # every call went through the sandbox: recorded and policy-checked
    assert [c.name for c in sandbox.calls] == ["file_read", "file_read", "email_read"]
    assert sandbox.calls[0].allowed
    assert not sandbox.calls[1].allowed and sandbox.calls[1].policy_violations
    # optional arguments that were not passed are not forwarded as None
    assert sandbox.calls[2].arguments == {}


async def test_factory_with_one_or_zero_parameters(sandbox: ToolSandbox, context: TargetContext) -> None:
    def tools_only(tools: list[Any]) -> Any:
        return RunnableLambda(lambda payload: f"{len(tools)} tools")

    def no_args() -> Any:
        return RunnableLambda(lambda payload: {"messages": [HumanMessage(content="q"), AIMessage(content="graph")]})

    first = await LangChainTarget("a:b", obj=tools_only).send(CONVERSATION, sandbox, context)
    assert first.text == f"{len(sandbox.names)} tools"
    second = await LangChainTarget("a:b", obj=no_args).send(CONVERSATION, sandbox, context)
    assert second.text == "graph"


def test_sandbox_tool_schemas(sandbox: ToolSandbox) -> None:
    tools = {t.name: t for t in sandbox_tools(sandbox)}
    payment = tools["payment_transfer"].args
    assert set(payment) == {"amount", "to_account", "currency"}
    schema = tools["payment_transfer"].args_schema.model_json_schema()  # type: ignore[union-attr]
    assert set(schema["required"]) == {"amount", "to_account"}
    assert schema["properties"]["amount"]["type"] == "number"
    db_schema = tools["db_query"].args_schema.model_json_schema()  # type: ignore[union-attr]
    assert db_schema["properties"]["where"]["anyOf"][0]["type"] == "object"
    assert tools["file_read"].description == "Read a file from the workspace."


async def test_optional_arguments_accept_explicit_null(sandbox: ToolSandbox) -> None:
    tools = {t.name: t for t in sandbox_tools(sandbox)}
    await tools["email_read"].ainvoke({"folder": None, "limit": 2})
    assert sandbox.calls[0].arguments == {"limit": 2}


@pytest.mark.parametrize(
    ("value", "text"),
    [
        ("plain", "plain"),
        (AIMessage(content="ai"), "ai"),
        ({"output": "out"}, "out"),
        ({"output": AIMessage(content="nested")}, "nested"),
        ({"messages": [AIMessage(content="first"), AIMessage(content="last")]}, "last"),
        ({"messages": [{"role": "assistant", "content": "dict message"}]}, "dict message"),
        ({"role": "assistant", "content": "bare dict"}, "bare dict"),
    ],
)
def test_text_extraction(value: Any, text: str) -> None:
    assert _text_of(value) == text


@pytest.mark.parametrize("value", [42, {"messages": []}, {"other": 1}, AIMessage(content=[{"type": "image"}])])
def test_text_extraction_failure(value: Any) -> None:
    with pytest.raises(TargetError, match="cannot extract text"):
        _text_of(value)


async def test_runnable_errors(sandbox: ToolSandbox, context: TargetContext) -> None:
    def explode(payload: dict[str, Any]) -> str:
        raise ValueError("chain exploded")

    with pytest.raises(TargetError, match="LangChain runnable failed: chain exploded"):
        await LangChainTarget("a:b", obj=RunnableLambda(explode)).send(CONVERSATION, sandbox, context)

    def target_error(payload: dict[str, Any]) -> str:
        raise TargetError("upstream 503", retryable=True)

    with pytest.raises(TargetError, match="upstream 503") as info:
        await LangChainTarget("a:b", obj=RunnableLambda(target_error)).send(CONVERSATION, sandbox, context)
    assert info.value.retryable is True

    with pytest.raises(TargetError, match="cannot extract text"):
        await LangChainTarget("a:b", obj=RunnableLambda(lambda p: 7)).send(CONVERSATION, sandbox, context)


async def test_neither_runnable_nor_factory(sandbox: ToolSandbox, context: TargetContext) -> None:
    with pytest.raises(ConfigError, match="neither a Runnable nor a factory"):
        await LangChainTarget("a:b", obj=42).send(CONVERSATION, sandbox, context)


async def test_build_from_config_file(tmp_path: Path, sandbox: ToolSandbox, context: TargetContext) -> None:
    module = tmp_path / "lc_agent_mod.py"
    module.write_text(
        "from langchain_core.runnables import RunnableLambda\n"
        "chain = RunnableLambda(lambda payload: 'file chain: ' + payload['input'])\n"
    )
    target = build_target(TargetConfig(type="langchain", path=f"{module}:chain"))
    assert isinstance(target, LangChainTarget)
    response = await target.send(CONVERSATION, sandbox, context)
    assert response.text == "file chain: summarize the readme"


def test_missing_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lc_module, "langchain_available", lambda: False)
    with pytest.raises(ConfigError, match=r"agentguard\[langchain\]"):
        LangChainTarget("a:b", obj=object())


def test_langchain_available_without_package(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    monkeypatch.setitem(sys.modules, "langchain_core", None)
    assert langchain_available() is False
