"""Instrumented mock tools.

Each tool has a JSON-schema spec and a pure implementation over a :class:`VirtualEnvironment`.
Tools never touch the real filesystem, network, shell or payment systems: side effects are
recorded in the environment (``sent_emails``, ``transfers``, ``http_log``, ``shell_log``).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agentguard.harness.environment import VirtualEnvironment
from agentguard.llm.base import LLMToolSpec

__all__ = ["TOOL_REGISTRY", "ToolArgumentError", "ToolSpec", "execute_tool", "validate_arguments"]


class ToolArgumentError(ValueError):
    """Raised when tool arguments do not satisfy the tool schema."""


@dataclass(frozen=True)
class ToolSpec:
    """A tool definition: name, description, JSON schema and implementation."""

    name: str
    description: str
    parameters: dict[str, Any]
    impl: Callable[[VirtualEnvironment, dict[str, Any]], str]

    def to_llm(self) -> LLMToolSpec:
        """Convert to the provider-neutral LLM tool spec."""
        return LLMToolSpec(name=self.name, description=self.description, parameters=self.parameters)


def _schema(required: list[str], **props: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": props,
        "required": required,
        "additionalProperties": False,
    }


_TYPES: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "number": (int, float),
    "integer": (int,),
    "object": (dict,),
    "boolean": (bool,),
}


def validate_arguments(spec: ToolSpec, arguments: dict[str, Any]) -> dict[str, Any]:
    """Validate ``arguments`` against ``spec.parameters`` (types, required, no extras).

    Returns:
        The arguments with numeric strings coerced for ``number`` fields.

    Raises:
        ToolArgumentError: on any schema violation.
    """
    if not isinstance(arguments, dict):
        raise ToolArgumentError(f"{spec.name}: arguments must be an object")
    props: dict[str, Any] = spec.parameters.get("properties", {})
    cleaned: dict[str, Any] = {}
    for key in spec.parameters.get("required", []):
        if key not in arguments:
            raise ToolArgumentError(f"{spec.name}: missing required argument '{key}'")
    for key, value in arguments.items():
        if key not in props:
            raise ToolArgumentError(f"{spec.name}: unexpected argument '{key}'")
        expected = props[key].get("type", "string")
        if expected == "number" and isinstance(value, str):
            try:
                value = float(value.replace(",", ""))
            except ValueError as exc:
                raise ToolArgumentError(f"{spec.name}: '{key}' must be a number") from exc
        if isinstance(value, bool) and expected in {"number", "integer"}:
            raise ToolArgumentError(f"{spec.name}: '{key}' must be a {expected}")
        if not isinstance(value, _TYPES.get(expected, (object,))):
            raise ToolArgumentError(f"{spec.name}: '{key}' must be of type {expected}")
        cleaned[key] = value
    return cleaned


def _override(env: VirtualEnvironment, name: str, default: str) -> str:
    extra = env.tool_output_overrides.get(name)
    return f"{default}\n{extra}" if extra else default


def _email_send(env: VirtualEnvironment, a: dict[str, Any]) -> str:
    env.sent_emails.append({"to": a["to"], "subject": a.get("subject", ""), "body": a.get("body", "")})
    return f"Queued 1 outgoing item for {a['to']} (simulated; nothing left the sandbox)."


def _email_read(env: VirtualEnvironment, a: dict[str, Any]) -> str:
    limit = int(a.get("limit", 5))
    messages = env.inbox[-limit:]
    lines = [f"From: {m.sender}\nSubject: {m.subject}\n\n{m.body}" for m in reversed(messages)]
    return _override(env, "email_read", "\n---\n".join(lines) or "Inbox is empty.")


def _file_read(env: VirtualEnvironment, a: dict[str, Any]) -> str:
    path = str(a["path"])
    content = env.files.get(path)
    if content is None:
        return f"Error: file not found: {path}"
    return _override(env, "file_read", content)


def _file_write(env: VirtualEnvironment, a: dict[str, Any]) -> str:
    env.files[str(a["path"])] = str(a["content"])
    return f"Wrote {len(str(a['content']))} bytes to {a['path']} (virtual filesystem)."


def _http_get(env: VirtualEnvironment, a: dict[str, Any]) -> str:
    url = str(a["url"])
    env.http_log.append(url)
    page = env.web.get(url) or env.web.get(url.rstrip("/")) or env.web.get(url.rstrip("/") + "/")
    if page is None:
        page = f"<html><body>404 Not Found: {url}</body></html>"
    return _override(env, "http_get", page)


def _db_query(env: VirtualEnvironment, a: dict[str, Any]) -> str:
    table = str(a["table"])
    if table not in env.db:
        return f"Error: unknown table '{table}'. Tables: {', '.join(sorted(env.db))}"
    rows = env.query(table, a.get("where") or {})
    return _override(env, "db_query", env.dump_rows(rows))


def _shell_exec(env: VirtualEnvironment, a: dict[str, Any]) -> str:
    env.shell_log.append(str(a["command"]))
    return f"[simulated shell] command recorded but not executed: {a['command']}"


def _payment_transfer(env: VirtualEnvironment, a: dict[str, Any]) -> str:
    ref = f"TX-{len(env.transfers) + 1:05d}"
    env.transfers.append(
        {
            "amount": a["amount"],
            "to_account": a["to_account"],
            "currency": a.get("currency", "USD"),
            "ref": ref,
        }
    )
    return f"Payment {ref} queued (simulated): {a['amount']} {a.get('currency', 'USD')}, beneficiary {a['to_account']}."


def _memory_write(env: VirtualEnvironment, a: dict[str, Any]) -> str:
    env.memory.write(str(a["key"]), str(a["value"]), source="agent")
    return f"Saved memory note '{a['key']}'."


def _memory_read(env: VirtualEnvironment, a: dict[str, Any]) -> str:
    entries = env.memory.read(str(a.get("key", "*")))
    return _override(env, "memory_read", "\n".join(f"{e.key}: {e.value}" for e in entries) or "No memory notes.")


def _search_docs(env: VirtualEnvironment, a: dict[str, Any]) -> str:
    k = int(a.get("k", 3))
    docs = env.rag.search(str(a["query"]), k=max(1, min(k, 10)))
    if not docs:
        return _override(env, "search_docs", "No matching documents.")
    return _override(env, "search_docs", "\n\n".join(f"[doc:{d.doc_id}] {d.title}\n{d.text.strip()}" for d in docs))


_STR = {"type": "string"}
TOOL_REGISTRY: dict[str, ToolSpec] = {
    spec.name: spec
    for spec in [
        ToolSpec(
            "email_send",
            "Send an e-mail.",
            _schema(["to", "body"], to=_STR, subject=_STR, body=_STR),
            _email_send,
        ),
        ToolSpec(
            "email_read",
            "Read recent e-mails from the user's inbox.",
            _schema([], folder=_STR, limit={"type": "integer"}),
            _email_read,
        ),
        ToolSpec("file_read", "Read a file from the workspace.", _schema(["path"], path=_STR), _file_read),
        ToolSpec(
            "file_write",
            "Write a file in the workspace.",
            _schema(["path", "content"], path=_STR, content=_STR),
            _file_write,
        ),
        ToolSpec("http_get", "Fetch a web page.", _schema(["url"], url=_STR), _http_get),
        ToolSpec(
            "db_query",
            "Query a database table with equality filters.",
            _schema(["table"], table=_STR, where={"type": "object"}),
            _db_query,
        ),
        ToolSpec("shell_exec", "Run a shell command.", _schema(["command"], command=_STR), _shell_exec),
        ToolSpec(
            "payment_transfer",
            "Transfer money to an account.",
            _schema(["amount", "to_account"], amount={"type": "number"}, to_account=_STR, currency=_STR),
            _payment_transfer,
        ),
        ToolSpec(
            "memory_write",
            "Save a long-term memory note.",
            _schema(["key", "value"], key=_STR, value=_STR),
            _memory_write,
        ),
        ToolSpec("memory_read", "Read long-term memory notes.", _schema([], key=_STR), _memory_read),
        ToolSpec(
            "search_docs",
            "Search the company knowledge base.",
            _schema(["query"], query=_STR, k={"type": "integer"}),
            _search_docs,
        ),
    ]
}


def execute_tool(env: VirtualEnvironment, name: str, arguments: dict[str, Any]) -> str:
    """Validate and run a mock tool against ``env``.

    Raises:
        KeyError: unknown tool.
        ToolArgumentError: invalid arguments.
    """
    spec = TOOL_REGISTRY[name]
    cleaned = validate_arguments(spec, arguments)
    return spec.impl(env, cleaned)


def canonical_args(arguments: dict[str, Any]) -> str:
    """Canonical JSON string of arguments (used to match approvals to calls)."""
    return json.dumps(arguments, sort_keys=True, default=str)
