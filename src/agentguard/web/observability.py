"""Logging, request tracing and (optional) error reporting for the hosted web app.

* **Structured logs.** In production every log line is one JSON object (``ts``, ``level``,
  ``logger``, ``msg`` and request fields), which Render's log viewer and log drains can search.
  Messages pass through :func:`agentguard.web.security.redact` before they are written.
* **Request log.** One line per request: method, path (never the query string), status,
  duration and a request id, which is also returned in the ``X-Request-ID`` header so a user can
  quote it in a bug report.
* **Error alerts (optional).** With ``SENTRY_DSN`` set, unhandled errors and ``logger.error``
  calls are sent to Sentry, which e-mails you. Request bodies, cookies, headers, local variables
  and user details are never sent, and every string is scrubbed of secret-looking values.
"""

from __future__ import annotations

import contextvars
import json
import logging
import re
import secrets
import sys
import time
from typing import Any

from agentguard.web.security import redact

__all__ = ["RequestLogMiddleware", "configure_logging", "init_sentry", "request_id_var", "scrub_event"]

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9\-]{8,64}$")
_QUIET_PATHS = {"/healthz", "/readyz", "/static/htmx.min.js"}
_EXTRA_FIELDS = ("method", "path", "status", "duration_ms", "scan_id", "user_id")

logger = logging.getLogger("agentguard.web.access")


class JsonFormatter(logging.Formatter):
    """One JSON object per line, with secrets redacted from the message."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": redact(record.getMessage()),
        }
        request_id = request_id_var.get()
        if request_id:
            payload["request_id"] = request_id
        for name in _EXTRA_FIELDS:
            value = getattr(record, name, None)
            if value is not None:
                payload[name] = value
        if record.exc_info and record.exc_info[0] is not None:
            payload["error_type"] = record.exc_info[0].__name__
            # Frames only (file, line, function): exception messages and locals can hold secrets.
            payload["stack"] = self.formatStack("".join(_frames(record.exc_info[2])))
        return json.dumps(payload, ensure_ascii=False)


def _frames(tb: Any) -> list[str]:
    import traceback

    return [f"{f.filename}:{f.lineno} in {f.name}\n" for f in traceback.extract_tb(tb)[-8:]]


class TextFormatter(logging.Formatter):
    """Human-readable lines for development, also redacted."""

    def format(self, record: logging.LogRecord) -> str:
        record = logging.makeLogRecord(record.__dict__)
        record.msg, record.args = redact(record.getMessage()), None
        line = super().format(record)
        request_id = request_id_var.get()
        return f"{line} [req {request_id}]" if request_id else line


def configure_logging(*, json_logs: bool, level: str = "INFO") -> None:
    """Route the app's and uvicorn's logs through one redacting handler on stdout."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        JsonFormatter() if json_logs else TextFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    for name in ("uvicorn", "uvicorn.error"):
        uvicorn_logger = logging.getLogger(name)
        uvicorn_logger.handlers[:] = []
        uvicorn_logger.propagate = True
    # The request log below replaces uvicorn's access log, which would include query strings.
    logging.getLogger("uvicorn.access").disabled = True


class RequestLogMiddleware:
    """Pure ASGI middleware: request id + one structured log line per request."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        incoming = dict(scope.get("headers") or []).get(b"x-request-id", b"").decode("latin-1")
        request_id = incoming if _REQUEST_ID.match(incoming) else secrets.token_hex(8)
        token = request_id_var.set(request_id)
        started = time.perf_counter()
        status = 500

        async def send_with_id(message: dict[str, Any]) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
                message.setdefault("headers", [])
                message["headers"] = [*message["headers"], (b"x-request-id", request_id.encode())]
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        finally:
            path = str(scope.get("path", ""))[:200]
            if path not in _QUIET_PATHS or status >= 400:
                logger.log(
                    logging.WARNING if status >= 500 else logging.INFO,
                    "%s %s %s",
                    scope.get("method", ""),
                    path,
                    status,
                    extra={
                        "method": scope.get("method", ""),
                        "path": path,
                        "status": status,
                        "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                    },
                )
            request_id_var.reset(token)


_DROP_REQUEST_KEYS = ("data", "cookies", "headers", "query_string", "env")


def scrub_event(event: dict[str, Any], hint: dict[str, Any] | None = None) -> dict[str, Any]:
    """Sentry ``before_send``: drop request payloads and user data, redact every string."""
    request = event.get("request")
    if isinstance(request, dict):
        for key in _DROP_REQUEST_KEYS:
            request.pop(key, None)
        if isinstance(request.get("url"), str):
            request["url"] = request["url"].split("?", 1)[0]
    event.pop("user", None)
    return _redact_all(event)  # type: ignore[no-any-return]


def _redact_all(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {key: _redact_all(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_all(item) for item in value]
    return value


def init_sentry(dsn: str | None, *, environment: str, release: str) -> bool:
    """Enable Sentry error reporting when ``dsn`` is set; returns whether it was enabled."""
    if not dsn:
        return False
    import sentry_sdk

    sentry_sdk.init(
        dsn=dsn,
        environment=environment,
        release=f"agentguard@{release}",
        send_default_pii=False,
        include_local_variables=False,  # locals can hold API keys and agent credentials
        max_request_body_size="never",
        traces_sample_rate=0.0,
        before_send=scrub_event,  # type: ignore[arg-type]
        before_breadcrumb=lambda crumb, hint: _redact_all(crumb),
    )
    return True
