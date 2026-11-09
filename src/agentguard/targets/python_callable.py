"""Target adapter for a Python callable (``path/to/file.py:attr`` or ``package.module:attr``)."""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import inspect
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agentguard.core.errors import ConfigError, TargetError
from agentguard.harness.sandbox import ToolSandbox
from agentguard.llm.base import LLMMessage
from agentguard.targets.base import BaseTarget, TargetContext, TargetResponse

__all__ = ["PythonCallableTarget", "load_object", "normalize_response"]


def load_object(spec: str) -> Any:
    """Import ``module:attr`` or ``file.py:attr`` and return the attribute.

    Raises:
        ConfigError: when the module, file or attribute cannot be loaded.
    """
    if ":" not in spec:
        raise ConfigError(f"target.path: expected 'module:attr' or 'file.py:attr' (got {spec!r})")
    module_part, attr = spec.rsplit(":", 1)
    try:
        if module_part.endswith(".py") or "/" in module_part:
            path = Path(module_part).resolve()
            if not path.exists():
                raise ConfigError(f"target.path: file not found: {module_part}")
            module_name = f"agentguard_user_{path.stem}_{abs(hash(str(path))) % 10**8}"
            if str(path.parent) not in sys.path:
                sys.path.insert(0, str(path.parent))
            module = sys.modules.get(module_name)
            if module is None:
                spec_obj = importlib.util.spec_from_file_location(module_name, path)
                if spec_obj is None or spec_obj.loader is None:
                    raise ConfigError(f"target.path: cannot import {module_part}")
                module = importlib.util.module_from_spec(spec_obj)
                sys.modules[module_name] = module
                spec_obj.loader.exec_module(module)
        else:
            module = importlib.import_module(module_part)
    except ConfigError:
        raise
    except Exception as exc:
        raise ConfigError(f"target.path: failed to import {module_part}: {exc}") from exc
    try:
        return getattr(module, attr)
    except AttributeError as exc:
        raise ConfigError(f"target.path: {module_part} has no attribute {attr!r}") from exc


def normalize_response(value: Any) -> TargetResponse:
    """Convert a callable's return value (str, dict or TargetResponse) to a TargetResponse.

    Raises:
        TargetError: for unsupported return types (a malformed response).
    """
    if isinstance(value, TargetResponse):
        return value
    if isinstance(value, str):
        return TargetResponse(text=value)
    if isinstance(value, bytes):
        return TargetResponse(text=value.decode("utf-8", errors="replace"))
    if isinstance(value, dict):
        for key in ("text", "output", "response", "answer", "content"):
            if key in value and isinstance(value[key], (str, bytes)):
                text = value[key]
                if isinstance(text, bytes):
                    text = text.decode("utf-8", errors="replace")
                contexts = value.get("retrieved_contexts") or value.get("contexts") or []
                return TargetResponse(text=text, retrieved_contexts=[str(c) for c in contexts])
    raise TargetError(f"malformed target response of type {type(value).__name__}", retryable=False)


class PythonCallableTarget(BaseTarget):
    """Calls a Python function, sync or async.

    Supported signatures: ``f(conversation, tools, context)``, ``f(conversation)``, or
    ``f(message: str)``. Sync functions run in a worker thread; inside them, use
    ``tools.call_sync`` wrappers via ``context.extra['call_tool']``.
    """

    type_name = "python_callable"

    def __init__(self, path: str, *, obj: Callable[..., Any] | None = None) -> None:
        self.path = path
        self.func: Callable[..., Any] = obj if obj is not None else load_object(path)
        if not callable(self.func):
            raise ConfigError(f"target.path: {path} is not callable")
        try:
            self._arity = len(inspect.signature(self.func).parameters)
        except (TypeError, ValueError):
            self._arity = 3

    @property
    def name(self) -> str:
        """Display name: the callable spec."""
        return self.path

    def describe(self) -> dict[str, Any]:
        """Report metadata."""
        return {"path": self.path}

    async def send(self, conversation: list[LLMMessage], tools: ToolSandbox, context: TargetContext) -> TargetResponse:
        """Invoke the callable with the conversation."""
        if self._arity >= 3:
            args: tuple[Any, ...] = (conversation, tools, context)
        elif self._arity == 1:
            last_user = next((m.content for m in reversed(conversation) if m.role == "user"), "")
            args = (last_user,)
        else:
            args = (conversation,)
        if inspect.iscoroutinefunction(self.func) or inspect.iscoroutinefunction(
            getattr(self.func, "__call__", None)  # noqa: B004 - callable objects
        ):
            result = await self.func(*args)
        else:
            loop = asyncio.get_running_loop()

            def call_sync(name: str, arguments: dict[str, Any]) -> str:
                future = asyncio.run_coroutine_threadsafe(tools.call(name, arguments), loop)
                return future.result().content

            context.extra.setdefault("call_tool", call_sync)
            result = await asyncio.to_thread(self.func, *args)
            if inspect.isawaitable(result):
                result = await result
        return normalize_response(result)
