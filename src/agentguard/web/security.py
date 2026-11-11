"""Security primitives: password hashing, session tokens, CSRF, rate limiting, headers, redaction."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

__all__ = [
    "BodySizeLimitMiddleware",
    "RateLimiter",
    "SecurityHeadersMiddleware",
    "client_ip",
    "constant_time_equals",
    "hash_password",
    "hash_token",
    "new_token",
    "password_problem",
    "rate_key",
    "redact",
    "verify_password",
]

# OWASP-recommended argon2id parameters (m=19 MiB, t=2, p=1) — cheap enough for small instances.
_HASHER = PasswordHasher(time_cost=2, memory_cost=19 * 1024, parallelism=1)
# Equalizes timing between "unknown email" and "wrong password".
_DUMMY_HASH = _HASHER.hash("agentguard-dummy-password-for-timing")
_COMMON = frozenset(
    [
        "password123!",
        "password1234",
        "qwertyuiop12",
        "123456789012",
        "letmein12345",
        "adminadmin12",
        "welcome12345",
        "iloveyou1234",
        "changeme1234",
        "passwordpassword",
    ]
)


# Each argon2 operation allocates ~19 MiB. Running them on a small dedicated pool bounds both
# concurrency and resident memory: glibc keeps freed buffers in per-thread arenas, so hashing on
# the (40-thread) request pool would retain ~19 MiB in every request thread after a login flood.
_HASH_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="argon2")


def hash_password(password: str) -> str:
    """argon2id hash of ``password``."""
    return _HASH_POOL.submit(_HASHER.hash, password).result()


def _verify(password_hash: str | None, password: str) -> bool:
    try:
        return _HASHER.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def verify_password(password_hash: str | None, password: str) -> bool:
    """Constant-effort verification (a dummy hash is checked when the user does not exist)."""
    return _HASH_POOL.submit(_verify, password_hash, password).result()


def password_problem(password: str, email: str) -> str | None:
    """Reason a password is unacceptable, or ``None`` (NIST 800-63B style: length over complexity)."""
    if len(password) < 12:
        return "Password must be at least 12 characters."
    if len(password) > 128:
        return "Password must be at most 128 characters."
    if len(set(password)) < 5:
        return "Password is too repetitive."
    local = email.split("@", 1)[0].lower()
    if len(local) >= 4 and local in password.lower():
        return "Password must not contain your e-mail name."
    if password.lower() in _COMMON:
        return "Password is too common."
    return None


def new_token(nbytes: int = 32) -> str:
    """URL-safe random token from the OS CSPRNG."""
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """SHA-256 hex digest used to store bearer tokens (sessions) without storing the token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_equals(a: str | None, b: str | None) -> bool:
    """Timing-safe string comparison (``False`` if either is empty)."""
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def client_ip(request: Request, trusted_hops: int) -> str:
    """Client IP, honouring ``X-Forwarded-For`` only for ``trusted_hops`` reverse proxies."""
    peer = request.client.host if request.client else ""
    if trusted_hops <= 0:
        return peer
    forwarded = [part.strip() for part in request.headers.get("x-forwarded-for", "").split(",") if part.strip()]
    if len(forwarded) >= trusted_hops:
        return forwarded[-trusted_hops][:64]
    return peer


def rate_key(ip: str) -> str:
    """Rate-limit bucket for an address: IPv6 clients are grouped by /64 (one subscriber's prefix)."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip[:64]
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.IPv6Network(f"{address}/64", strict=False))
    return str(address)


class RateLimiter:
    """In-memory sliding-window limiter (per process; see docs/DEPLOYMENT.md for scaling)."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()  # sync routes run on a thread pool

    def allow(self, key: str, limit: int, window_seconds: float) -> bool:
        """Record a hit for ``key``; False if it exceeds ``limit`` within the window."""
        with self._lock:
            return self._allow(key, limit, window_seconds)

    def _allow(self, key: str, limit: int, window_seconds: float) -> bool:
        now = self._clock()
        hits = self._hits[key]
        while hits and now - hits[0] > window_seconds:
            hits.popleft()
        if len(hits) >= limit:
            return False
        hits.append(now)
        if len(self._hits) > 50_000:  # bound memory under abuse
            for stale in [k for k, v in self._hits.items() if not v or now - v[-1] > window_seconds][:10_000]:
                del self._hits[stale]
        return True

    def reset(self, key: str) -> None:
        """Forget ``key`` (e.g. after a successful login)."""
        with self._lock:
            self._hits.pop(key, None)


_SECRETISH = [
    re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),  # Google API keys
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-]{12,}"),
]


def redact(text: str, *secrets_: str | None) -> str:
    """Remove known secrets and secret-looking tokens from user-visible/logged text."""
    for secret in secrets_:
        if secret and len(secret) >= 4:
            # also the JSON-escaped form, since stored results are redacted after serialization
            for form in dict.fromkeys((secret, json.dumps(secret)[1:-1], json.dumps(secret, ensure_ascii=False)[1:-1])):
                text = text.replace(form, "[REDACTED]")
    for pattern in _SECRETISH:
        text = pattern.sub(lambda m: (m.group(1) if m.lastindex else "") + "[REDACTED]", text)
    return text


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds a nonce-based CSP and hardening headers to every response.

    Routes may set ``request.state.csp_sandbox = True`` to serve untrusted HTML (scan reports) in
    a sandboxed, opaque origin.
    """

    def __init__(self, app: object, *, hsts: bool) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self.hsts = hsts

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        """Generate a per-request nonce, run the request, then set headers."""
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce
        response = await call_next(request)
        csp = (
            "default-src 'none'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "form-action 'self'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'"
        )
        if getattr(request.state, "csp_sandbox", False):
            csp += "; sandbox allow-scripts allow-popups allow-downloads"
        headers = response.headers
        headers["Content-Security-Policy"] = csp
        headers["X-Content-Type-Options"] = "nosniff"
        headers["X-Frame-Options"] = "DENY"
        headers["Referrer-Policy"] = "no-referrer"
        headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        headers["Cross-Origin-Opener-Policy"] = "same-origin"
        headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if "cache-control" not in headers:
            headers["Cache-Control"] = "no-store"
        if self.hsts:
            headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response


class BodySizeLimitMiddleware:
    """Pure ASGI middleware rejecting request bodies larger than ``max_bytes`` with 413.

    ``Content-Length`` is checked up front; streamed (chunked) bodies are counted as they arrive.
    Once the limit is crossed the body stream is ended (an ``http.disconnect`` is delivered, so
    nothing more is buffered) and whatever the application then responds is replaced by a 413.
    Raising from ``receive`` is avoided on purpose: Starlette's middleware wraps it in an
    exception group, which turns it into a generic error.
    """

    def __init__(self, app: Any, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = self.max_bytes + 1
                if declared > self.max_bytes:
                    await _reject_too_large(send)
                    return
        received = 0
        exceeded = False
        rejected = False

        async def limited_receive() -> dict[str, Any]:
            nonlocal received, exceeded
            if exceeded:
                return {"type": "http.disconnect"}
            message: dict[str, Any] = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    exceeded = True
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message: dict[str, Any]) -> None:
            nonlocal rejected
            if not exceeded:
                await send(message)
            elif not rejected:
                rejected = True
                await _reject_too_large(send)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except Exception:
            if not exceeded:
                raise
        if exceeded and not rejected:
            await _reject_too_large(send)


async def _reject_too_large(send: Any) -> None:
    body = b"Request body too large"
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [(b"content-type", b"text/plain; charset=utf-8"), (b"content-length", str(len(body)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": body})
