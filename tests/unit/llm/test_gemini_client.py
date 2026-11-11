"""Gemini REST client, exercised against httpx.MockTransport (no network, no real key)."""

from __future__ import annotations

import json

import httpx
import pytest

from agentguard.config.models import JudgeConfig, LLMConfig
from agentguard.core.errors import ConfigError
from agentguard.llm.base import LLMMessage
from agentguard.llm.factory import build_llm
from agentguard.llm.gemini_client import GeminiClient, GeminiError, list_gemini_models

FAKE_KEY = "AIzaFAKE-test-key-0123456789abcdefghijk"


def _ok(text: str) -> dict[str, object]:
    return {
        "candidates": [{"content": {"role": "model", "parts": [{"text": text}]}}],
        "usageMetadata": {"promptTokenCount": 11, "candidatesTokenCount": 3},
    }


async def test_request_shape_and_response_parsing() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_ok('{"verdict": "safe"}'))

    client = GeminiClient(FAKE_KEY, "models/gemini-2.5-flash", transport=httpx.MockTransport(handler))
    response = await client.complete(
        [
            LLMMessage(role="system", content="judge"),
            LLMMessage(role="user", content="hi"),
            LLMMessage(role="assistant", content="yo"),
            LLMMessage(role="user", content="again"),
        ],
        json_mode=True,
        max_tokens=50,
    )
    request = seen[0]
    assert request.url.path.endswith("/models/gemini-2.5-flash:generateContent")
    assert request.headers["x-goog-api-key"] == FAKE_KEY
    assert FAKE_KEY not in str(request.url)  # never in the query string (logs/proxies)
    body = json.loads(request.content)
    assert body["systemInstruction"]["parts"][0]["text"] == "judge"
    assert [c["role"] for c in body["contents"]] == ["user", "model", "user"]
    assert body["generationConfig"] == {
        "temperature": 0.0,
        "responseMimeType": "application/json",
        "maxOutputTokens": 50,
    }
    assert response.text == '{"verdict": "safe"}'
    assert (response.tokens_in, response.tokens_out, response.cost_usd) == (11, 3, 0.0)


async def test_errors_never_contain_the_key_and_retry_on_429() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, json={"error": {"message": "quota"}})
        return httpx.Response(400, json={"error": {"message": f"API key not valid: {FAKE_KEY}"}})

    client = GeminiClient(FAKE_KEY, transport=httpx.MockTransport(handler), max_retries=2)
    client_retry_fast = client
    import agentguard.llm.gemini_client as module

    original = module.backoff
    module.backoff = lambda *_a, **_k: original(0.0, 0.0)  # type: ignore[assignment]
    try:
        with pytest.raises(GeminiError) as info:
            await client_retry_fast.complete([LLMMessage(role="user", content="x")])
    finally:
        module.backoff = original  # type: ignore[assignment]
    assert calls["n"] == 2
    assert FAKE_KEY not in str(info.value)
    assert "[REDACTED]" in str(info.value)
    assert FAKE_KEY not in repr(client)


async def test_blocked_prompt_is_reported() -> None:
    transport = httpx.MockTransport(lambda r: httpx.Response(200, json={"promptFeedback": {"blockReason": "SAFETY"}}))
    with pytest.raises(GeminiError, match="SAFETY"):
        await GeminiClient(FAKE_KEY, transport=transport).complete([LLMMessage(role="user", content="x")])


async def test_list_models_filters_generate_content_and_paginates() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("pageToken") == "p2":
            return httpx.Response(
                200,
                json={"models": [{"name": "models/gemini-2.5-pro", "supportedGenerationMethods": ["generateContent"]}]},
            )
        return httpx.Response(
            200,
            json={
                "nextPageToken": "p2",
                "models": [
                    {
                        "name": "models/gemini-2.5-flash",
                        "supportedGenerationMethods": ["generateContent", "countTokens"],
                    },
                    {"name": "models/text-embedding-004", "supportedGenerationMethods": ["embedContent"]},
                ],
            },
        )

    assert await list_gemini_models(FAKE_KEY, transport=httpx.MockTransport(handler)) == [
        "gemini-2.5-flash",
        "gemini-2.5-pro",
    ]


async def test_list_models_rejects_bad_key() -> None:
    transport = httpx.MockTransport(lambda r: httpx.Response(400, json={"error": {"message": "API key not valid"}}))
    with pytest.raises(GeminiError, match="400"):
        await list_gemini_models(FAKE_KEY, transport=transport)


def test_factory_requires_key_and_config_never_serializes_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(ConfigError):
        build_llm(LLMConfig(provider="gemini", model="gemini-2.5-flash"))
    config = LLMConfig(provider="gemini", model="gemini-2.5-flash", api_key=FAKE_KEY)
    assert isinstance(build_llm(config), GeminiClient)
    judge = JudgeConfig(provider="gemini", model="gemini-2.5-flash", api_key=FAKE_KEY)
    for dumped in (config.model_dump_json(), repr(config), judge.model_dump_json(), str(judge.model_dump())):
        assert FAKE_KEY not in dumped
    with pytest.raises(ConfigError):
        GeminiClient("  ")
