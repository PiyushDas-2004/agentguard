"""OpenAICompatibleTarget against a fake OpenAI-compatible server served in-process by uvicorn."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from agentguard.config.models import LLMConfig, TargetConfig
from agentguard.core.errors import ConfigError, TargetError
from agentguard.harness.sandbox import ToolSandbox
from agentguard.llm.base import LLMMessage
from agentguard.targets.base import TargetContext
from agentguard.targets.openai_compat import OpenAICompatibleTarget
from agentguard.targets.registry import build_target

from .conftest import free_port, serve


def _completion(
    message: dict[str, Any], *, prompt: int = 0, completion: int = 0, model: str = "fake"
) -> dict[str, Any]:
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", **message}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": prompt, "completion_tokens": completion},
    }


def _tool_call(name: str, arguments: str, call_id: str = "call_1") -> dict[str, Any]:
    return {"id": call_id, "type": "function", "function": {"name": name, "arguments": arguments}}


def fake_openai_app(requests: list[dict[str, Any]]) -> FastAPI:
    """Behaviour is selected by the requested ``model`` name."""
    app = FastAPI()

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/chat/completions")
    async def completions(request: Request) -> Response:
        body = await request.json()
        requests.append({"body": body, "authorization": request.headers.get("authorization")})
        model = body["model"]
        tool_messages = [m for m in body["messages"] if m["role"] == "tool"]
        if model == "tool-then-answer":
            if not tool_messages:
                return JSONResponse(
                    _completion(
                        {
                            "content": None,
                            "tool_calls": [_tool_call("file_read", '{"path": "/sandbox/public/readme.txt"}')],
                        },
                        prompt=11,
                        completion=5,
                    )
                )
            return JSONResponse(
                _completion(
                    {"content": "Final: " + tool_messages[-1]["content"][:40]},
                    prompt=20,
                    completion=7,
                    model="served-model",
                )
            )
        if model == "bad-arguments":
            if not tool_messages:
                calls = [
                    _tool_call("file_read", "{not json", "c1"),
                    _tool_call("memory_write", '["a", "list"]', "c2"),
                    {"type": "function", "function": {}},
                ]
                return JSONResponse(_completion({"content": "thinking", "tool_calls": calls}))
            return JSONResponse({"choices": [{"message": {"content": None}}]})
        if model == "always-tools":
            return JSONResponse(
                _completion({"tool_calls": [_tool_call("shell_exec", '{"command": "id"}')]}, prompt=1, completion=1)
            )
        if model == "rate-limited":
            return JSONResponse({"error": "slow down"}, status_code=429)
        if model == "bad-request":
            return JSONResponse({"error": "bad"}, status_code=400)
        if model == "no-choices":
            return JSONResponse({"id": "x", "choices": []})
        if model == "list-body":
            return JSONResponse([1, 2, 3])
        if model == "not-json":
            return PlainTextResponse("upstream proxy error page")
        if model == "auth-echo":
            return JSONResponse(_completion({"content": request.headers.get("authorization") or "<none>"}))
        return JSONResponse(_completion({"content": f"echo {body['messages'][-1]['content']}"}))

    return app


@pytest.fixture(scope="module")
def server() -> Iterator[tuple[str, list[dict[str, Any]]]]:
    requests: list[dict[str, Any]] = []
    with serve(fake_openai_app(requests)) as base:
        yield base + "/v1", requests


@pytest.fixture
def api(server: tuple[str, list[dict[str, Any]]]) -> str:
    server[1].clear()
    return server[0]


@pytest.fixture
def requests_seen(server: tuple[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    return server[1]


def user(text: str) -> list[LLMMessage]:
    return [LLMMessage(role="user", content=text)]


async def test_tool_call_then_final_answer(
    api: str, requests_seen: list[dict[str, Any]], sandbox: ToolSandbox, context: TargetContext
) -> None:
    context.system_context = "Deployment: staging"
    target = OpenAICompatibleTarget(api + "/", "tool-then-answer")
    assert target.url == api + "/chat/completions"
    try:
        response = await target.send(user("read the readme"), sandbox, context)
    finally:
        await target.aclose()
    # the tool ran in the sandbox and its output was fed back to the model
    assert [c.name for c in sandbox.calls] == ["file_read"]
    assert sandbox.calls[0].arguments == {"path": "/sandbox/public/readme.txt"}
    assert sandbox.calls[0].allowed
    assert response.text.startswith("Final: ")
    assert (response.tokens_in, response.tokens_out) == (31, 12)
    assert response.model == "served-model"
    first, second = (r["body"] for r in requests_seen)
    assert [m["role"] for m in first["messages"]] == ["system", "system", "user"]
    assert first["messages"][0]["content"] == context.system_prompt
    assert first["messages"][1]["content"] == "Deployment: staging"
    names = {t["function"]["name"] for t in first["tools"]}
    assert {"file_read", "email_send", "shell_exec"} <= names
    assert [m["role"] for m in second["messages"]] == ["system", "system", "user", "assistant", "tool"]
    assert second["messages"][-1]["tool_call_id"] == "call_1"
    assert second["messages"][-1]["content"][:300] == sandbox.calls[0].result_preview
    assert requests_seen[0]["authorization"] is None


async def test_malformed_tool_arguments_are_tolerated(api: str, sandbox: ToolSandbox, context: TargetContext) -> None:
    target = OpenAICompatibleTarget(api, "bad-arguments")
    response = await target.send(user("go"), sandbox, context)
    await target.aclose()
    # unparsable / non-object arguments become {}; a nameless function becomes an unknown tool
    assert [(c.name, c.arguments) for c in sandbox.calls] == [("file_read", {}), ("memory_write", {}), ("", {})]
    assert "unknown tool ''" in sandbox.calls[2].policy_violations
    assert response.text == ""
    assert response.model == "bad-arguments"


async def test_tool_step_limit(
    api: str, requests_seen: list[dict[str, Any]], sandbox: ToolSandbox, context: TargetContext
) -> None:
    target = OpenAICompatibleTarget(api, "always-tools", max_tool_steps=2)
    response = await target.send(user("loop forever"), sandbox, context)
    await target.aclose()
    assert response.text == "[agentguard] tool step limit reached"
    assert len(requests_seen) == 3  # max_tool_steps + 1 model calls
    assert [c.name for c in sandbox.calls] == ["shell_exec"] * 3
    assert all(not c.allowed for c in sandbox.calls)
    assert (response.tokens_in, response.tokens_out) == (3, 3)


async def test_no_system_prompt_and_no_tools(
    api: str, requests_seen: list[dict[str, Any]], make_sandbox: Any, context: TargetContext
) -> None:
    sandbox = make_sandbox(tool_names=[])
    target = OpenAICompatibleTarget(api, "echo", send_system_prompt=False)
    response = await target.send(user("hello"), sandbox, context)
    await target.aclose()
    assert response.text == "echo hello"
    body = requests_seen[0]["body"]
    assert "tools" not in body
    assert [m["role"] for m in body["messages"]] == ["user"]


async def test_full_url_and_api_key_header(api: str, sandbox: ToolSandbox, context: TargetContext) -> None:
    target = OpenAICompatibleTarget(api + "/chat/completions", "auth-echo", api_key="sk-test-123")
    assert target.url == api + "/chat/completions"
    response = await target.send(user("who am i"), sandbox, context)
    await target.aclose()
    assert response.text == "Bearer sk-test-123"
    assert target.name == f"auth-echo @ {api}/chat/completions"
    assert target.describe() == {"url": api + "/chat/completions", "model": "auth-echo", "max_tool_steps": 8}
    assert "sk-test" not in json.dumps(target.describe())


@pytest.mark.parametrize(
    ("model", "match", "retryable"),
    [
        ("rate-limited", "HTTP 429", True),
        ("bad-request", "HTTP 400", False),
        ("no-choices", "missing 'choices'", False),
        ("list-body", "missing 'choices'", False),
        ("not-json", "non-JSON response", False),
    ],
)
async def test_error_responses(
    api: str, sandbox: ToolSandbox, context: TargetContext, model: str, match: str, retryable: bool
) -> None:
    target = OpenAICompatibleTarget(api, model)
    with pytest.raises(TargetError, match=match) as info:
        await target.send(user("x"), sandbox, context)
    await target.aclose()
    assert info.value.retryable is retryable
    assert sandbox.calls == []


async def test_connection_error_is_retryable(sandbox: ToolSandbox, context: TargetContext) -> None:
    target = OpenAICompatibleTarget(f"http://127.0.0.1:{free_port()}/v1", "m", timeout=2)
    with pytest.raises(TargetError, match="HTTP error calling") as info:
        await target.send(user("x"), sandbox, context)
    await target.aclose()
    assert info.value.retryable is True


async def test_timeout_is_retryable(sandbox: ToolSandbox, context: TargetContext) -> None:
    import asyncio

    app = FastAPI()

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/chat/completions")
    async def slow() -> dict[str, str]:
        await asyncio.sleep(2)
        return {}

    with serve(app) as base:
        target = OpenAICompatibleTarget(base + "/v1", "m", timeout=0.2)
        with pytest.raises(TargetError, match="timeout calling") as info:
            await target.send(user("x"), sandbox, context)
        await target.aclose()
    assert info.value.retryable is True


def test_from_config_api_key_env(api: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AG_FAKE_OPENAI_KEY", "sk-from-env")
    config = TargetConfig(
        type="openai_compat",
        url=api,
        model="tool-then-answer",
        api_key_env="AG_FAKE_OPENAI_KEY",
        max_tool_steps=3,
        options={"send_system_prompt": False, "timeout": 5},
    )
    target = build_target(config)
    assert isinstance(target, OpenAICompatibleTarget)
    assert target.api_key == "sk-from-env"
    assert (target.model, target.max_tool_steps, target.send_system_prompt, target.timeout) == (
        "tool-then-answer",
        3,
        False,
        5.0,
    )

    monkeypatch.delenv("AG_FAKE_OPENAI_KEY")
    with pytest.raises(ConfigError, match="AG_FAKE_OPENAI_KEY is not set"):
        build_target(config)


def test_from_config_model_fallbacks(api: str) -> None:
    from_llm = build_target(TargetConfig(type="openai_compat", url=api, llm=LLMConfig(model="llm-model")))
    assert isinstance(from_llm, OpenAICompatibleTarget)
    assert from_llm.model == "llm-model"
    assert from_llm.api_key is None
    default = build_target(TargetConfig(type="openai_compat", url=api))
    assert isinstance(default, OpenAICompatibleTarget)
    assert default.model == "gpt-4o-mini"
