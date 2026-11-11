"""Security primitives: password hashing, session tokens, CSRF, rate limiting, headers, redaction."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

__all__ = [
    "RateLimiter",
    "SecurityHeadersMiddleware",
    "client_ip",
    "constant_time_equals",
    "hash_password",
    "hash_token",
    "new_token",
    "password_problem",
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


def hash_password(password: str) -> str:
    """argon2id hash of ``password``."""
    return _HASHER.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Constant-effort verification (a dummy hash is checked when the user does not exist)."""
    try:
        return _HASHER.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


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


class RateLimiter:
    """In-memory sliding-window limiter (per process; see docs/DEPLOYMENT.md for scaling)."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: int, window_seconds: float) -> bool:
        """Record a hit for ``key``; False if it exceeds ``limit`` within the window."""
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
            text = text.replace(secret, "[REDACTED]")
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
