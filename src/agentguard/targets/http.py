"""HTTP target: any JSON-over-HTTP chat endpoint.

The request body is rendered from a Jinja2 template (``target.request_template``) with the
variables ``message`` (latest user text), ``messages`` (list of ``{role, content}``),
``system_prompt``, ``session`` and ``case_id``. Headers support ``${ENV_VAR}`` interpolation.
The reply text and (optionally) the tool calls the remote agent reports are extracted with JSONPath
(``target.response_mapping``).
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from jinja2 import StrictUndefined, TemplateError
from jinja2.sandbox import SandboxedEnvironment
from jsonpath_ng.exceptions import JsonPathParserError
from jsonpath_ng.parser import parse as jsonpath_parse

from agentguard.config.loader import interpolate_env
from agentguard.config.models import ResponseMapping, TargetConfig
from agentguard.core.errors import ConfigError, TargetError
from agentguard.core.types import ToolCall
from agentguard.harness.sandbox import ToolSandbox
from agentguard.llm.base import LLMMessage
from agentguard.targets.base import BaseTarget, TargetContext, TargetResponse

__all__ = ["DEFAULT_TEMPLATE", "HTTPTarget"]

DEFAULT_TEMPLATE = '{"message": {{ message | tojson }}, "messages": {{ messages | tojson }}, "session": {{ session }}}'
RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}


def _compile(expr: str) -> Any:
    try:
        return jsonpath_parse(expr)
    except (JsonPathParserError, Exception) as exc:
        raise ConfigError(f"target.response_mapping: invalid JSONPath {expr!r}: {exc}") from exc


class HTTPTarget(BaseTarget):
    """Calls an HTTP endpoint once per user turn.

    Args:
        url: endpoint URL (``${VAR}`` allowed).
        method: HTTP method.
        headers: request headers (``${VAR}`` allowed).
        request_template: Jinja2 template producing the JSON body.
        mapping: JSONPath response mapping.
        timeout: client timeout in seconds.
        transport: optional httpx transport (tests).
    """

    type_name = "http"

    def __init__(
        self,
        url: str,
        *,
        method: str = "POST",
        headers: dict[str, str] | None = None,
        request_template: str | None = None,
        mapping: ResponseMapping | None = None,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.url = interpolate_env(url)
        self.method = method
        self.headers = {k: interpolate_env(v) for k, v in (headers or {}).items()}
        env = SandboxedEnvironment(undefined=StrictUndefined, autoescape=False)  # renders a JSON body, not HTML
        try:
            self.template = env.from_string(request_template or DEFAULT_TEMPLATE)
        except TemplateError as exc:
            raise ConfigError(f"target.request_template: {exc}") from exc
        self.mapping = mapping or ResponseMapping()
        self._text_path = _compile(self.mapping.text)
        self._calls_path = _compile(self.mapping.tool_calls) if self.mapping.tool_calls else None
        self.timeout = timeout
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    @classmethod
    def from_config(cls, config: TargetConfig) -> HTTPTarget:
        """Build from a ``TargetConfig``."""
        assert config.url is not None
        return cls(
            config.url,
            method=config.method,
            headers=config.headers,
            request_template=config.request_template,
            mapping=config.response_mapping,
            timeout=float(config.options.get("timeout", 30.0)),
        )

    @property
    def name(self) -> str:
        """Display name: the URL."""
        return self.url

    def describe(self) -> dict[str, Any]:
        """Report metadata (headers redacted)."""
        return {"url": self.url, "method": self.method, "headers": sorted(self.headers)}

    async def start(self) -> None:
        """Open the HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout, transport=self._transport)

    async def aclose(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def render_body(self, conversation: list[LLMMessage], context: TargetContext) -> str:
        """Render the request body for the current conversation."""
        latest = next((m.content for m in reversed(conversation) if m.role == "user"), "")
        try:
            return self.template.render(
                message=latest,
                messages=[{"role": m.role, "content": m.content} for m in conversation],
                system_prompt=context.system_prompt,
                session=context.session,
                case_id=context.case_id,
            )
        except TemplateError as exc:
            raise ConfigError(f"target.request_template: {exc}") from exc

    def parse(self, payload: Any) -> TargetResponse:
        """Extract text and reported tool calls from a JSON payload.

        Raises:
            TargetError: when the text path matches nothing (malformed response).
        """
        matches = self._text_path.find(payload)
        if not matches:
            raise TargetError(f"response did not match text path {self.mapping.text!r}", retryable=False)
        value = matches[0].value
        text = value if isinstance(value, str) else json.dumps(value)
        calls: list[ToolCall] = []
        if self._calls_path is not None:
            for match in self._calls_path.find(payload):
                items = match.value if isinstance(match.value, list) else [match.value]
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    args = item.get(self.mapping.tool_args_field) or {}
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except json.JSONDecodeError:
                            args = {"_raw": args}
                    calls.append(ToolCall(name=str(item.get(self.mapping.tool_name_field, "unknown")), arguments=args))
        return TargetResponse(text=text, tool_calls=calls, raw=None)

    async def send(self, conversation: list[LLMMessage], tools: ToolSandbox, context: TargetContext) -> TargetResponse:
        """POST the rendered body and parse the JSON response."""
        await self.start()
        assert self._client is not None
        body = self.render_body(conversation, context)
        try:
            response = await self._client.request(
                self.method,
                self.url,
                content=body.encode("utf-8"),
                headers={"Content-Type": "application/json", **self.headers},
            )
        except httpx.TimeoutException as exc:
            raise TargetError(f"HTTP timeout: {exc}", retryable=True) from exc
        except httpx.HTTPError as exc:
            raise TargetError(f"HTTP error: {exc}", retryable=True) from exc
        if response.status_code >= 400:
            raise TargetError(
                f"HTTP {response.status_code} from target",
                retryable=response.status_code in RETRYABLE_STATUS,
                status_code=response.status_code,
            )
        try:
            payload = response.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise TargetError(f"target returned non-JSON body: {response.text[:200]!r}", retryable=False) from exc
        return self.parse(payload)
