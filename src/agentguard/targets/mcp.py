"""MCP target (``agentguard[mcp]``): evaluate an agent equipped with an MCP server's tools.

AgentGuard launches the server over stdio, lists its tools and lets the configured model (the naive
mock offline) use them. Every MCP tool call is recorded through the sandbox's policy engine, so an
over-permissive server tool (e.g. reading outside the allowed path) shows up as a policy violation.
Tool descriptions are shown to the model, which makes tool-description poisoning observable.
"""

from __future__ import annotations

import json
from contextlib import AsyncExitStack
from typing import Any

from agentguard.config.models import TargetConfig
from agentguard.core.errors import ConfigError, TargetError
from agentguard.harness.sandbox import ToolSandbox
from agentguard.llm.base import LLMMessage, LLMToolSpec
from agentguard.llm.mock import MockLLM
from agentguard.targets.base import BaseTarget, TargetContext, TargetResponse

__all__ = ["MCPTarget", "mcp_available"]


def mcp_available() -> bool:
    """Whether the ``mcp`` SDK can be imported."""
    try:
        import mcp  # noqa: F401
    except ImportError:
        return False
    return True


def _result_text(result: Any) -> str:
    parts = []
    for item in getattr(result, "content", []) or []:
        text = getattr(item, "text", None)
        parts.append(text if isinstance(text, str) else json.dumps(getattr(item, "model_dump", dict)()))
    return "\n".join(parts)


class MCPTarget(BaseTarget):
    """Stdio MCP server + model-driven tool loop.

    Args:
        command: server executable.
        args: server arguments.
        env: extra environment for the server process.
        max_tool_steps: maximum tool round-trips per user turn.
    """

    type_name = "mcp"

    def __init__(
        self, command: str, args: list[str] | None = None, *, env: dict[str, str] | None = None, max_tool_steps: int = 6
    ) -> None:
        if not mcp_available():
            raise ConfigError("the mcp target needs: pip install 'agentguard[mcp]'")
        self.command = command
        self.args = list(args or [])
        self.env = dict(env or {})
        self.max_tool_steps = max_tool_steps
        self._stack: AsyncExitStack | None = None
        self._session: Any = None
        self.tools: list[LLMToolSpec] = []

    @classmethod
    def from_config(cls, config: TargetConfig) -> MCPTarget:
        """Build from a ``TargetConfig``."""
        assert config.command is not None
        return cls(config.command, config.args, env=config.env, max_tool_steps=config.max_tool_steps)

    @property
    def name(self) -> str:
        """Display name."""
        return " ".join([self.command, *self.args])

    def describe(self) -> dict[str, Any]:
        """Report metadata including the server's tool list."""
        return {"command": self.command, "args": self.args, "tools": [t.name for t in self.tools]}

    async def start(self) -> None:
        """Launch the server and initialize the MCP session."""
        if self._session is not None:
            return
        import os
        import sys

        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        command = sys.executable if self.command in {"python", "python3"} else self.command
        params = StdioServerParameters(command=command, args=self.args, env={**os.environ, **self.env})
        stack = AsyncExitStack()
        try:
            read, write = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            listed = await session.list_tools()
        except Exception as exc:
            await stack.aclose()
            raise TargetError(f"failed to start MCP server {self.name!r}: {exc}") from exc
        self._stack, self._session = stack, session
        self.tools = [
            LLMToolSpec(
                name=t.name,
                description=t.description or "",
                parameters=dict(getattr(t, "input_schema", None) or getattr(t, "inputSchema", None) or {}),
            )
            for t in listed.tools
        ]

    async def aclose(self) -> None:
        """Shut down the session and server process."""
        if self._stack is not None:
            await self._stack.aclose()
        self._stack, self._session = None, None

    async def send(self, conversation: list[LLMMessage], tools: ToolSandbox, context: TargetContext) -> TargetResponse:
        """Let the model use the MCP tools to answer the latest user turn."""
        await self.start()
        llm = context.llm or MockLLM("vulnerable", seed=context.seed)
        catalogue = "\n".join(f"- {t.name}: {t.description}" for t in self.tools)
        messages = [
            LLMMessage(role="system", content=context.system_prompt),
            LLMMessage(role="system", name="context", content="Available MCP tools:\n" + catalogue),
            *conversation,
        ]
        for _ in range(self.max_tool_steps):
            response = await llm.complete(messages, self.tools, seed=context.seed)
            if not response.tool_calls:
                return TargetResponse(text=response.text)
            messages.append(LLMMessage(role="assistant", tool_calls=response.tool_calls))
            for call in response.tool_calls:
                try:
                    result = await self._session.call_tool(call.name, call.arguments)
                    text = _result_text(result)
                except Exception as exc:
                    text = f"Error: {exc}"
                tools.record_external(call.name, call.arguments, text)
                messages.append(LLMMessage(role="tool", name=call.name, tool_call_id=call.id, content=text))
        final = await llm.complete(messages, None, seed=context.seed)
        return TargetResponse(text=final.text)
