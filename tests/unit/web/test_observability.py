"""Structured logging, request ids and Sentry scrubbing never leak secrets."""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

import pytest

from agentguard.web import observability
from agentguard.web.observability import JsonFormatter, RequestLogMiddleware, init_sentry, scrub_event

FAKE_KEY = "AIzaSyFAKE0123456789abcdefghijklmnopqrstu"


def _record(message: str, exc: BaseException | None = None) -> logging.LogRecord:
    exc_info = (type(exc), exc, exc.__traceback__) if exc else None
    return logging.LogRecord("agentguard.web", logging.ERROR, __file__, 1, message, None, exc_info)


def test_json_logs_are_redacted_and_carry_only_stack_frames() -> None:
    try:
        raise RuntimeError(f"upstream rejected key {FAKE_KEY}")
    except RuntimeError as exc:
        error = exc
    line = JsonFormatter().format(_record(f"failed with {FAKE_KEY}", error))
    payload = json.loads(line)
    assert FAKE_KEY not in line
    assert payload["level"] == "error"
    assert "[REDACTED]" in payload["msg"]
    assert payload["error_type"] == "RuntimeError"
    assert "test_observability.py" in payload["stack"]


def test_scrub_event_drops_payloads_and_redacts() -> None:
    event: dict[str, Any] = {
        "request": {
            "url": "https://x/scans?token=abc",
            "data": {"gemini_api_key": FAKE_KEY},
            "cookies": {"s": "1"},
            "headers": {"Authorization": "Bearer abcdefghijklmnop"},
            "query_string": "token=abc",
        },
        "user": {"email": "a@example.com"},
        "exception": {"values": [{"value": f"bad key {FAKE_KEY}"}]},
    }
    cleaned = scrub_event(event)
    assert cleaned["request"] == {"url": "https://x/scans"}
    assert "user" not in cleaned
    assert FAKE_KEY not in json.dumps(cleaned)


def test_sentry_is_off_without_dsn_and_privacy_preserving_with_it(monkeypatch: pytest.MonkeyPatch) -> None:
    assert init_sentry(None, environment="production", release="1") is False
    captured: dict[str, Any] = {}
    fake = type(sys)("sentry_sdk")
    fake.init = lambda **kwargs: captured.update(kwargs)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sentry_sdk", fake)
    assert init_sentry("https://public@sentry.example/1", environment="production", release="1.0.0") is True
    assert captured["send_default_pii"] is False
    assert captured["include_local_variables"] is False
    assert captured["max_request_body_size"] == "never"
    assert captured["before_send"] is scrub_event


async def test_request_log_adds_request_id_and_omits_query(caplog: pytest.LogCaptureFixture) -> None:
    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b""}

    middleware = RequestLogMiddleware(app)
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/scans",
        "query_string": b"secret=1",
        "headers": [(b"x-request-id", b"abcdef1234567890")],
    }
    with caplog.at_level(logging.INFO, logger="agentguard.web.access"):
        await middleware(scope, receive, send)
        await middleware({**scope, "headers": [(b"x-request-id", b"bad id!")]}, receive, send)
    ids = [dict(m["headers"])[b"x-request-id"] for m in sent if m["type"] == "http.response.start"]
    assert ids[0] == b"abcdef1234567890"
    assert ids[1] != b"bad id!"
    assert len(ids[1]) == 16
    assert all("secret" not in r.getMessage() for r in caplog.records)
    assert caplog.records[0].path == "/scans"  # type: ignore[attr-defined]
    assert observability.request_id_var.get() == ""  # reset after the request
