"""LangChain / LangGraph target (``agentguard[langchain]``).

``target.path`` points at either a Runnable (invoked with ``{"input", "messages"}``) or a factory
``build(tools: list[BaseTool], llm) -> Runnable`` that receives AgentGuard's sandboxed tools as
LangChain ``StructuredTool`` objects, so tool use is recorded and policy-checked.
"""

from __future__ import annotations

import inspect
from typing import Any

from pydantic import create_model

from agentguard.config.models import TargetConfig
from agentguard.core.errors import ConfigError, TargetError
from agentguard.harness.sandbox import ToolSandbox
from agentguard.llm.base import LLMMessage
from agentguard.targets.base import BaseTarget, TargetContext, TargetResponse
from agentguard.targets.python_callable import load_object

__all__ = ["LangChainTarget", "langchain_available", "sandbox_tools"]

_JSON_TYPES: dict[str, Any] = {"string": str, "number": float, "integer": int, "object": dict, "boolean": bool}


def langchain_available() -> bool:
    """Whether ``langchain_core`` can be imported."""
    try:
        import langchain_core  # noqa: F401
    except ImportError:
        return False
    return True


def sandbox_tools(tools: ToolSandbox) -> list[Any]:
    """Wrap sandbox tools as LangChain ``StructuredTool`` objects."""
    from langchain_core.tools import StructuredTool

    wrapped: list[Any] = []
    for spec in tools.specs():
        props: dict[str, Any] = spec.parameters.get("properties", {})
        required = set(spec.parameters.get("required", []))
        fields: dict[str, Any] = {
            name: ((_JSON_TYPES.get(p.get("type", "string"), str)), ... if name in required else None)
            for name, p in props.items()
        }
        schema = create_model(f"{spec.name}_args", **fields)

        def make(name: str) -> Any:
            async def run(**kwargs: Any) -> str:
                arguments = {k: v for k, v in kwargs.items() if v is not None}
                return (await tools.call(name, arguments)).content

            return run

        wrapped.append(
            StructuredTool(name=spec.name, description=spec.description, args_schema=schema, coroutine=make(spec.name))
        )
    return wrapped


def _text_of(result: Any) -> str:
    if isinstance(result, str):
        return result
    content = getattr(result, "content", None)
    if isinstance(content, str):
        return content
    if isinstance(result, dict):
        if "output" in result:
            return _text_of(result["output"])
        if result.get("messages"):
            return _text_of(result["messages"][-1])
    raise TargetError(f"cannot extract text from LangChain result of type {type(result).__name__}")


class LangChainTarget(BaseTarget):
    """Invokes a LangChain Runnable / LangGraph graph."""

    type_name = "langchain"

    def __init__(self, path: str, *, obj: Any = None) -> None:
        if not langchain_available():
            raise ConfigError("the langchain target needs: pip install 'agentguard[langchain]'")
        self.path = path
        self.obj = obj if obj is not None else load_object(path)

    @classmethod
    def from_config(cls, config: TargetConfig) -> LangChainTarget:
        """Build from a ``TargetConfig``."""
        assert config.path is not None
        return cls(config.path)

    @property
    def name(self) -> str:
        """Display name."""
        return self.path

    def describe(self) -> dict[str, Any]:
        """Report metadata."""
        return {"path": self.path}

    def _runnable(self, tools: ToolSandbox, context: TargetContext) -> Any:
        if hasattr(self.obj, "ainvoke"):
            return self.obj
        if callable(self.obj):
            params = len(inspect.signature(self.obj).parameters)
            args = (sandbox_tools(tools), context.llm)[:params]
            return self.obj(*args)
        raise ConfigError(f"target.path: {self.path} is neither a Runnable nor a factory")

    async def send(self, conversation: list[LLMMessage], tools: ToolSandbox, context: TargetContext) -> TargetResponse:
        """Invoke the runnable with the conversation."""
        runnable = self._runnable(tools, context)
        latest = next((m.content for m in reversed(conversation) if m.role == "user"), "")
        payload = {
            "input": latest,
            "messages": [{"role": m.role, "content": m.content} for m in conversation],
            "system_prompt": context.system_prompt,
        }
        try:
            result = await runnable.ainvoke(payload)
        except TargetError:
            raise
        except Exception as exc:
            raise TargetError(f"LangChain runnable failed: {exc}") from exc
        return TargetResponse(text=_text_of(result))
