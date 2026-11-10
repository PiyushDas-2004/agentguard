"""PythonCallableTarget: signatures, sync/async, tool access, return normalization, loading errors."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Any

import pytest

from agentguard.core.errors import ConfigError, TargetError
from agentguard.core.types import ToolCall
from agentguard.harness.sandbox import ToolSandbox
from agentguard.llm.base import LLMMessage
from agentguard.targets.base import TargetContext, TargetResponse
from agentguard.targets.python_callable import PythonCallableTarget, load_object, normalize_response

CONVERSATION = [
    LLMMessage(role="user", content="first question"),
    LLMMessage(role="assistant", content="first answer"),
    LLMMessage(role="user", content="second question"),
]


# ---------------------------------------------------------------------------------------- signatures
async def test_one_arg_sync_receives_latest_user_text(sandbox: ToolSandbox, context: TargetContext) -> None:
    seen: list[Any] = []

    def echo(message: str) -> str:
        seen.append((message, threading.current_thread() is threading.main_thread()))
        return f"echo: {message}"

    target = PythonCallableTarget("inline:echo", obj=echo)
    response = await target.send(CONVERSATION, sandbox, context)
    assert response.text == "echo: second question"
    # sync callables run in a worker thread, never on the event loop thread
    assert seen == [("second question", False)]
    assert target.name == "inline:echo"
    assert target.describe() == {"path": "inline:echo"}


async def test_one_arg_without_user_turn_gets_empty_string(sandbox: ToolSandbox, context: TargetContext) -> None:
    target = PythonCallableTarget("x:y", obj=lambda message: f"<{message}>")
    response = await target.send([LLMMessage(role="system", content="sys")], sandbox, context)
    assert response.text == "<>"


async def test_two_arg_callable_receives_conversation(sandbox: ToolSandbox, context: TargetContext) -> None:
    def history(conversation: list[LLMMessage], _unused: object = None) -> str:
        return "|".join(m.role for m in conversation)

    response = await PythonCallableTarget("x:y", obj=history).send(CONVERSATION, sandbox, context)
    assert response.text == "user|assistant|user"


async def test_three_arg_async_uses_sandbox_and_context(sandbox: ToolSandbox, context: TargetContext) -> None:
    async def agent(conversation: list[LLMMessage], tools: ToolSandbox, ctx: TargetContext) -> dict[str, Any]:
        result = await tools.call("file_read", {"path": "/sandbox/private/notes.txt"})
        return {"text": f"{ctx.case_id}:{len(conversation)}:{result.call.name}"}

    response = await PythonCallableTarget("x:y", obj=agent).send(CONVERSATION, sandbox, context)
    assert response.text == "CASE-001:3:file_read"
    assert len(sandbox.calls) == 1
    call = sandbox.calls[0]
    # the example policy only allows /sandbox/public/ reads -> recorded as a violation
    assert not call.allowed
    assert call.policy_violations


async def test_sync_three_arg_callable_uses_call_tool(sandbox: ToolSandbox, context: TargetContext) -> None:
    def agent(conversation: list[LLMMessage], tools: ToolSandbox, ctx: TargetContext) -> str:
        call_tool = ctx.extra["call_tool"]
        listing = call_tool("memory_write", {"key": "k", "value": "v"})
        return f"wrote: {listing}"

    response = await PythonCallableTarget("x:y", obj=agent).send(CONVERSATION, sandbox, context)
    assert response.text.startswith("wrote: ")
    assert [c.name for c in sandbox.calls] == ["memory_write"]
    assert sandbox.calls[0].executed


async def test_call_tool_does_not_override_user_option(sandbox: ToolSandbox, context: TargetContext) -> None:
    marker = object()
    context.extra["call_tool"] = marker

    def agent(conversation: list[LLMMessage], tools: ToolSandbox, ctx: TargetContext) -> str:
        return "same" if ctx.extra["call_tool"] is marker else "replaced"

    response = await PythonCallableTarget("x:y", obj=agent).send(CONVERSATION, sandbox, context)
    assert response.text == "same"


async def test_async_callable_object(sandbox: ToolSandbox, context: TargetContext) -> None:
    class Agent:
        def __init__(self) -> None:
            self.calls = 0

        async def __call__(self, conversation: list[LLMMessage], tools: ToolSandbox, ctx: TargetContext) -> str:
            self.calls += 1
            return f"call {self.calls}"

    agent = Agent()
    target = PythonCallableTarget("x:y", obj=agent)
    assert (await target.send(CONVERSATION, sandbox, context)).text == "call 1"
    assert (await target.send(CONVERSATION, sandbox, context)).text == "call 2"


async def test_sync_callable_object(sandbox: ToolSandbox, context: TargetContext) -> None:
    class Agent:
        def __call__(self, message: str) -> bytes:
            return message.upper().encode()

    response = await PythonCallableTarget("x:y", obj=Agent()).send(CONVERSATION, sandbox, context)
    assert response.text == "SECOND QUESTION"


async def test_sync_callable_returning_awaitable(sandbox: ToolSandbox, context: TargetContext) -> None:
    async def later(message: str) -> str:
        await asyncio.sleep(0)
        return f"later {message}"

    def factory(message: str) -> Any:
        return later(message)

    response = await PythonCallableTarget("x:y", obj=factory).send(CONVERSATION, sandbox, context)
    assert response.text == "later second question"


async def test_uninspectable_callable_defaults_to_three_args(
    sandbox: ToolSandbox, context: TargetContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agentguard.targets.python_callable as module

    def agent(*args: Any) -> str:
        return str(len(args))

    def boom(_obj: Any) -> Any:
        raise ValueError("no signature")

    monkeypatch.setattr(module.inspect, "signature", boom)
    target = PythonCallableTarget("x:y", obj=agent)
    assert target._arity == 3
    assert (await target.send(CONVERSATION, sandbox, context)).text == "3"


# ---------------------------------------------------------------------------------------- returns
@pytest.mark.parametrize(
    ("value", "text"),
    [
        ("plain", "plain"),
        (b"by\xfftes", "by�tes"),
        ({"text": "t"}, "t"),
        ({"output": "o"}, "o"),
        ({"response": "r"}, "r"),
        ({"answer": "a"}, "a"),
        ({"content": b"c"}, "c"),
    ],
)
def test_normalize_response_text(value: Any, text: str) -> None:
    assert normalize_response(value).text == text


def test_normalize_response_contexts_and_passthrough() -> None:
    response = normalize_response({"text": "t", "retrieved_contexts": ["a", 2]})
    assert response.retrieved_contexts == ["a", "2"]
    assert normalize_response({"answer": "x", "contexts": ["c"]}).retrieved_contexts == ["c"]
    original = TargetResponse(text="keep", tool_calls=[ToolCall(name="t")])
    assert normalize_response(original) is original


@pytest.mark.parametrize("value", [42, None, ["text"], {"text": 1}, {"other": "x"}])
def test_normalize_response_malformed(value: Any) -> None:
    with pytest.raises(TargetError, match="malformed target response") as info:
        normalize_response(value)
    assert info.value.retryable is False


async def test_target_response_returned_as_is(sandbox: ToolSandbox, context: TargetContext) -> None:
    async def agent(message: str) -> TargetResponse:
        return TargetResponse(text="direct", tokens_in=3, tokens_out=4, model="m")

    response = await PythonCallableTarget("x:y", obj=agent).send(CONVERSATION, sandbox, context)
    assert (response.text, response.tokens_in, response.tokens_out, response.model) == ("direct", 3, 4, "m")


async def test_malformed_return_raises_target_error(sandbox: ToolSandbox, context: TargetContext) -> None:
    target = PythonCallableTarget("x:y", obj=lambda message: 12345)
    with pytest.raises(TargetError, match="int"):
        await target.send(CONVERSATION, sandbox, context)


async def test_callable_exception_propagates(sandbox: ToolSandbox, context: TargetContext) -> None:
    def broken(message: str) -> str:
        raise RuntimeError("agent crashed")

    with pytest.raises(RuntimeError, match="agent crashed"):
        await PythonCallableTarget("x:y", obj=broken).send(CONVERSATION, sandbox, context)


# ---------------------------------------------------------------------------------------- loading
def test_load_object_from_file_and_module(repo_root: Path) -> None:
    agent = load_object("examples/targets/vulnerable_agent.py:agent")
    assert callable(agent)
    # loading twice reuses the cached module
    assert load_object("examples/targets/vulnerable_agent.py:agent") is agent
    absolute = load_object(f"{repo_root}/examples/targets/vulnerable_agent.py:agent")
    assert absolute is agent
    assert load_object("agentguard.targets.python_callable:load_object") is load_object


async def test_target_built_from_file_path(sandbox: ToolSandbox, context: TargetContext) -> None:
    target = PythonCallableTarget("examples/targets/hardened_agent.py:agent")
    response = await target.send([LLMMessage(role="user", content="What are your opening hours?")], sandbox, context)
    assert isinstance(response.text, str)
    assert response.text


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ("no_colon_here", "expected 'module:attr'"),
        ("examples/targets/missing.py:agent", "file not found"),
        ("examples/targets/vulnerable_agent.py:nope", "has no attribute 'nope'"),
        ("agentguard_no_such_module_xyz:attr", "failed to import"),
        ("agentguard.version:missing_attr", "has no attribute"),
    ],
)
def test_load_object_errors(spec: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        load_object(spec)


def test_load_object_broken_file(tmp_path: Path) -> None:
    broken = tmp_path / "broken_agent.py"
    broken.write_text("raise ImportError('boom at import')\n")
    with pytest.raises(ConfigError, match="boom at import"):
        load_object(f"{broken}:agent")


def test_load_object_non_python_file(tmp_path: Path) -> None:
    data = tmp_path / "data" / "agent.txt"
    data.parent.mkdir()
    data.write_text("not python")
    with pytest.raises(ConfigError, match="cannot import"):
        load_object(f"{data}:agent")


def test_non_callable_target_rejected() -> None:
    with pytest.raises(ConfigError, match="is not callable"):
        PythonCallableTarget("agentguard.version:__version__")
