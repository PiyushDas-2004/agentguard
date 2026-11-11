"""Native Google Gemini client (REST ``generateContent``).

* The API key travels only in the ``x-goog-api-key`` header — never in URLs — so it cannot end
  up in proxy or access logs, and it is never included in exception messages.
* Retries 429 / 5xx / timeouts with exponential backoff and jitter.
* ``json_mode`` sets ``responseMimeType: application/json`` (used by the LLM judge).
* Usage is reported from ``usageMetadata``. Cost is reported as 0: with bring-your-own-key the
  provider bills the key owner directly and prices change; AgentGuard does not guess.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
from tenacity import AsyncRetrying, retry_if_exception, stop_after_attempt

from agentguard.core.errors import ConfigError, TargetError
from agentguard.core.retry import backoff
from agentguard.llm.base import BaseLLM, LLMMessage, LLMResponse, LLMToolSpec

__all__ = ["GEMINI_API", "GeminiClient", "GeminiError", "list_gemini_models", "redact_secret"]

GEMINI_API = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"


class GeminiError(TargetError):
    """A Gemini API call failed (message never contains the API key)."""


def redact_secret(text: str, secret: str | None) -> str:
    """Remove every occurrence of ``secret`` (and its URL-encoded form) from ``text``."""
    if not secret:
        return text
    import urllib.parse

    for form in {secret, urllib.parse.quote(secret, safe="")}:
        text = text.replace(form, "[REDACTED]")
    return text


def _retryable(exc: BaseException) -> bool:
    return isinstance(exc, GeminiError) and exc.retryable


def _error_message(response: httpx.Response) -> str:
    try:
        payload = response.json()
        message = str(payload.get("error", {}).get("message", ""))[:300]
    except ValueError:
        message = ""
    return message or f"HTTP {response.status_code}"


class GeminiClient(BaseLLM):
    """Gemini chat client.

    Args:
        api_key: Gemini API key (bring-your-own-key; held only in memory).
        model: model id, e.g. ``gemini-2.5-flash`` (``models/`` prefix optional).
        temperature: default sampling temperature.
        max_retries: retries for retryable failures.
        timeout: per-request timeout in seconds.
        transport: optional httpx transport (tests).
    """

    def __init__(
        self,
        api_key: str,
        model: str | None = None,
        *,
        temperature: float = 0.0,
        max_retries: int = 3,
        timeout: float = 60.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not api_key or not api_key.strip():
            raise ConfigError("a Gemini API key is required")
        self._api_key = api_key.strip()
        self.model = (model or DEFAULT_GEMINI_MODEL).removeprefix("models/")
        self.model_name = self.model
        self.temperature = temperature
        self.max_retries = max_retries
        self.timeout = timeout
        self._transport = transport

    def __repr__(self) -> str:
        return f"GeminiClient(model={self.model!r}, api_key=[REDACTED])"

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=GEMINI_API,
            headers={"x-goog-api-key": self._api_key, "content-type": "application/json"},
            timeout=self.timeout,
            transport=self._transport,
            follow_redirects=False,
        )

    @staticmethod
    def build_body(
        messages: list[LLMMessage], *, temperature: float, json_mode: bool, max_tokens: int | None
    ) -> dict[str, Any]:
        """Translate provider-neutral messages into a ``generateContent`` request body."""
        system = "\n\n".join(m.content for m in messages if m.role == "system" and m.content)
        contents: list[dict[str, Any]] = []
        for message in messages:
            if message.role == "system":
                continue
            role = "model" if message.role == "assistant" else "user"
            text = message.content
            if message.role == "tool":
                text = f"[tool result {message.name or ''}]\n{message.content}"
            if contents and contents[-1]["role"] == role:
                contents[-1]["parts"].append({"text": text})
            else:
                contents.append({"role": role, "parts": [{"text": text}]})
        if not contents:
            contents = [{"role": "user", "parts": [{"text": ""}]}]
        config: dict[str, Any] = {"temperature": temperature}
        if json_mode:
            config["responseMimeType"] = "application/json"
        if max_tokens is not None:
            config["maxOutputTokens"] = max_tokens
        body: dict[str, Any] = {"contents": contents, "generationConfig": config}
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        return body

    async def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        try:
            async with self._client() as client:
                response = await client.post(f"/models/{self.model}:generateContent", json=body)
        except httpx.TimeoutException:
            raise GeminiError("Gemini request timed out", retryable=True) from None
        except httpx.HTTPError as exc:
            raise GeminiError(f"Gemini connection error: {type(exc).__name__}", retryable=True) from None
        if response.status_code >= 400:
            retryable = response.status_code == 429 or response.status_code >= 500
            message = redact_secret(_error_message(response), self._api_key)
            raise GeminiError(
                f"Gemini API error {response.status_code}: {message}",
                retryable=retryable,
                status_code=response.status_code,
            )
        try:
            data = response.json()
        except ValueError:
            raise GeminiError("Gemini returned a non-JSON response") from None
        if not isinstance(data, dict):
            raise GeminiError("Gemini returned an unexpected payload")
        return data

    async def complete(
        self,
        messages: list[LLMMessage],
        tools: list[LLMToolSpec] | None = None,
        *,
        seed: int | None = None,
        temperature: float | None = None,
        json_mode: bool = False,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        """Generate a completion (tool calling is not used by AgentGuard's judge/attacker)."""
        body = self.build_body(
            messages,
            temperature=self.temperature if temperature is None else temperature,
            json_mode=json_mode,
            max_tokens=max_tokens,
        )
        started = time.perf_counter()
        retrying = AsyncRetrying(
            stop=stop_after_attempt(self.max_retries + 1),
            wait=backoff(1.0, 20.0),
            retry=retry_if_exception(_retryable),
            reraise=True,
        )
        data: dict[str, Any] = {}
        async for attempt in retrying:
            with attempt:
                data = await self._post(body)
        candidates = data.get("candidates") or []
        if not candidates:
            reason = data.get("promptFeedback", {}).get("blockReason", "no candidates")
            raise GeminiError(f"Gemini returned no answer ({reason})")
        parts = (candidates[0].get("content") or {}).get("parts") or []
        text = "".join(str(p.get("text", "")) for p in parts if isinstance(p, dict))
        usage = data.get("usageMetadata") or {}
        return LLMResponse(
            text=text,
            model=self.model,
            tokens_in=int(usage.get("promptTokenCount", 0) or 0),
            tokens_out=int(usage.get("candidatesTokenCount", 0) or 0),
            cost_usd=0.0,
            latency_ms=(time.perf_counter() - started) * 1000,
        )


async def list_gemini_models(
    api_key: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    timeout: float = 20.0,  # noqa: ASYNC109 - passed to httpx
) -> list[str]:
    """Validate ``api_key`` and return model ids that support ``generateContent``.

    Raises:
        GeminiError: invalid key or API failure (message never contains the key).
    """
    client = GeminiClient(api_key, transport=transport, timeout=timeout)
    models: list[str] = []
    page_token: str | None = None
    async with client._client() as http:
        for _ in range(10):
            params = {"pageSize": "100", **({"pageToken": page_token} if page_token else {})}
            try:
                response = await http.get("/models", params=params)
            except httpx.HTTPError as exc:
                raise GeminiError(f"Gemini connection error: {type(exc).__name__}", retryable=True) from None
            if response.status_code >= 400:
                message = redact_secret(_error_message(response), api_key)
                raise GeminiError(
                    f"Gemini API error {response.status_code}: {message}", status_code=response.status_code
                )
            payload = response.json()
            for model in payload.get("models", []):
                if "generateContent" in model.get("supportedGenerationMethods", []):
                    models.append(str(model.get("name", "")).removeprefix("models/"))
            page_token = payload.get("nextPageToken")
            if not page_token:
                break
    return sorted(m for m in models if m)
