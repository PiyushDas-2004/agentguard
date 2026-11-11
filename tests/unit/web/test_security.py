"""Password policy, tokens, rate limiting, redaction, client IP, templates and settings guards."""

from __future__ import annotations

import json

import pytest
from starlette.requests import Request

from agentguard.core.errors import ConfigError
from agentguard.web.jobs import validate_hosted_template
from agentguard.web.scans import REQUEST_PRESETS
from agentguard.web.security import (
    BodySizeLimitMiddleware,
    RateLimiter,
    client_ip,
    constant_time_equals,
    hash_password,
    hash_token,
    new_token,
    password_problem,
    rate_key,
    redact,
    verify_password,
)
from agentguard.web.settings import WebSettings, load_settings


def test_argon2_round_trip_and_rejections() -> None:
    stored = hash_password("correct horse battery")
    assert stored.startswith("$argon2id$")
    assert verify_password(stored, "correct horse battery")
    assert not verify_password(stored, "correct horse batterY")
    assert not verify_password(None, "anything")  # unknown user: dummy hash, still False
    assert not verify_password("not-a-hash", "anything")


@pytest.mark.parametrize(
    ("password", "problem"),
    [
        ("short", "at least 12"),
        ("a" * 129, "at most 128"),
        ("aaaaaaaaaaaaaaab", "repetitive"),
        ("alice-is-great-2026", "e-mail name"),
        ("password1234", "common"),
    ],
)
def test_password_policy(password: str, problem: str) -> None:
    assert problem in (password_problem(password, "alice@example.com") or "")


def test_good_password_accepted() -> None:
    assert password_problem("correct horse battery", "alice@example.com") is None


def test_tokens_are_random_and_hashed() -> None:
    a, b = new_token(), new_token()
    assert a != b
    assert len(a) >= 40
    assert hash_token(a) != a
    assert len(hash_token(a)) == 64
    assert constant_time_equals(a, a)
    assert not constant_time_equals(a, b)
    assert not constant_time_equals("", "")
    assert not constant_time_equals(None, a)


def test_rate_limiter_sliding_window() -> None:
    now = [0.0]
    limiter = RateLimiter(clock=lambda: now[0])
    assert all(limiter.allow("k", 3, 10) for _ in range(3))
    assert not limiter.allow("k", 3, 10)
    now[0] = 11
    assert limiter.allow("k", 3, 10)
    limiter.reset("k")
    assert all(limiter.allow("k", 3, 10) for _ in range(2))


def test_redaction_of_known_and_secret_looking_values() -> None:
    text = (
        "key AIzaSyA1234567890abcdefghijklmnopqrstuv and sk-abcdefghijklmnopqrstuvwx"
        " and Bearer abc.def-ghi_jkl and mine-123"
    )
    cleaned = redact(text, "mine-123")
    assert "AIza" not in cleaned
    assert "sk-abc" not in cleaned
    assert "abc.def" not in cleaned
    assert "mine-123" not in cleaned
    assert cleaned.count("[REDACTED]") == 4


def _request(peer: str, forwarded: str | None) -> Request:
    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded else []
    return Request({"type": "http", "headers": headers, "client": (peer, 1234), "method": "GET", "path": "/"})


def test_client_ip_trusts_only_configured_proxy_hops() -> None:
    spoofed = "6.6.6.6, 203.0.113.9"  # client sent 6.6.6.6; the proxy appended the real address
    assert client_ip(_request("10.0.0.2", spoofed), 1) == "203.0.113.9"
    assert client_ip(_request("10.0.0.2", spoofed), 0) == "10.0.0.2"
    assert client_ip(_request("10.0.0.2", None), 1) == "10.0.0.2"


@pytest.mark.parametrize("template", list(REQUEST_PRESETS.values()))
def test_presets_are_valid_hosted_templates(template: str) -> None:
    assert validate_hosted_template(template) is None


@pytest.mark.parametrize(
    "template",
    [
        '{"m": {{ message.__class__ }}}',
        '{"m": {{ cycler.__init__.__globals__ }}}',
        '{"m": {{ lipsum() }}}',
        '{"m": {{ "a" * 100000000 }}}',
        "{% for i in range(10**9) %}x{% endfor %}",
        "{# comment #}{{ message }}",
        '{"m": {{ message | attr("x") }}}',
        '{"m": {{ config }}}',
        '{"static": true}',
        '{"m": {{ message }}}' + "x" * 4000,
    ],
)
def test_dangerous_or_useless_templates_are_rejected(template: str) -> None:
    assert validate_hosted_template(template) is not None


def test_production_settings_refuse_insecure_configuration() -> None:
    with pytest.raises(ValueError, match="SECRET_KEY"):
        WebSettings(env="production", base_url="https://x.example.com", open_signup=True)
    with pytest.raises(ValueError, match="PRIVATE"):
        WebSettings(
            env="production",
            base_url="https://x.example.com",
            open_signup=True,
            secret_key="k" * 40,
            allow_private_targets=True,
        )
    with pytest.raises(ValueError, match="https"):
        WebSettings(env="production", base_url="http://x.example.com", open_signup=True, secret_key="k" * 40)
    with pytest.raises(ValueError, match="SIGNUP_CODE"):
        WebSettings(env="production", base_url="https://x.example.com", secret_key="k" * 40, signup_code="short")
    ok = WebSettings(env="production", base_url="https://x.example.com", secret_key="k" * 40, signup_code="c" * 16)
    assert ok.secure_cookies
    assert ok.production
    assert "k" * 40 not in repr(ok)
    assert "c" * 16 not in repr(ok)


def test_load_settings_from_environment() -> None:
    settings = load_settings(
        {
            "AGENTGUARD_ENV": "production",
            "AGENTGUARD_SECRET_KEY": "s" * 48,
            "AGENTGUARD_BASE_URL": "https://agentguard.example.com",
            "AGENTGUARD_SIGNUP_CODE": "invite-code-123456",
            "DATABASE_URL": "postgres://u:p@db:5432/agentguard",
            "AGENTGUARD_MAX_TRIALS": "2",
        }
    )
    assert settings.database_url == "postgresql+psycopg://u:p@db:5432/agentguard"
    assert settings.max_trials == 2
    with pytest.raises(ConfigError, match="insecure or invalid"):
        load_settings({"AGENTGUARD_ENV": "production"})


def test_redaction_covers_json_escaped_secrets() -> None:
    secret = 'pa"ss\\word-123'
    serialized = json.dumps({"echo": f"you sent {secret}"})
    assert secret not in redact(serialized, secret)
    assert json.dumps(secret)[1:-1] not in redact(serialized, secret)


def test_rate_keys_group_ipv6_by_prefix() -> None:
    assert rate_key("2001:db8:1:2:aaaa::1") == rate_key("2001:db8:1:2:bbbb::9") == "2001:db8:1:2::/64"
    assert rate_key("2001:db8:1:3::1") != rate_key("2001:db8:1:2::1")
    assert rate_key("203.0.113.9") == "203.0.113.9"
    assert rate_key("::ffff:203.0.113.9") == "203.0.113.9"


async def _call(app: BodySizeLimitMiddleware, chunks: list[bytes], declared: int | None) -> int:
    headers = [(b"content-length", str(declared).encode())] if declared is not None else []
    scope = {"type": "http", "method": "POST", "path": "/", "headers": headers}
    queue = [{"type": "http.request", "body": c, "more_body": i < len(chunks) - 1} for i, c in enumerate(chunks)]
    statuses: list[int] = []

    async def receive() -> dict[str, object]:
        return queue.pop(0)

    async def send(message: dict[str, object]) -> None:
        if message["type"] == "http.response.start":
            statuses.append(int(message["status"]))  # type: ignore[call-overload]

    await app(scope, receive, send)
    return statuses[0]


async def test_body_size_limit_rejects_declared_and_streamed_bodies() -> None:
    async def inner(scope: dict[str, object], receive: object, send: object) -> None:
        while True:
            message = await receive()  # type: ignore[operator]
            if not message.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})  # type: ignore[operator]
        await send({"type": "http.response.body", "body": b"ok"})  # type: ignore[operator]

    app = BodySizeLimitMiddleware(inner, max_bytes=1000)
    assert await _call(app, [b"x" * 10], 10) == 200
    assert await _call(app, [b"x" * 10], 5000) == 413  # declared too large: refused before reading
    assert await _call(app, [b"x" * 600, b"x" * 600], None) == 413  # chunked/streamed past the limit
