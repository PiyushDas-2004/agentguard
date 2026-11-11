"""SSRF-safe outbound HTTP for the hosted service.

A hosted scanner sends requests to user-supplied URLs, so every request must be prevented from
reaching internal infrastructure (loopback, private networks, cloud metadata endpoints, ...).

Defense layers implemented here:

1. **URL policy** (:func:`check_url`): ``https`` only (``http`` only when explicitly allowed), no
   embedded credentials, no IP-literal tricks bypassing checks, bounded length.
2. **Connect-time IP validation** (:class:`GuardedNetworkBackend`): DNS is resolved *at connect
   time* and **every** resolved address must be globally routable; the socket is then opened to a
   validated address. Because the check happens on the address actually connected to, DNS
   rebinding (validate one IP, connect to another) is not possible. TLS still verifies the
   certificate against the original hostname (SNI is unchanged).
3. **Origin pinning** (:class:`SafeTransport`): a transport can be restricted to a set of verified
   origins (scheme, host, port); requests to anything else are refused before any I/O.
4. **No ambient proxies, no redirects, bounded responses**: environment proxies are ignored (a
   proxy would resolve names on our behalf and bypass the IP checks), redirects are never
   followed, and response bodies are capped.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import typing
import urllib.parse
from collections.abc import AsyncIterator, Iterable
from dataclasses import dataclass, field

import anyio
import httpcore
import httpx

__all__ = [
    "BlockedAddressError",
    "GuardedNetworkBackend",
    "NetPolicy",
    "SafeTransport",
    "UnsafeURLError",
    "check_url",
    "ip_is_public",
    "origin_of",
    "safe_client",
]

MAX_URL_LENGTH = 2048
DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class UnsafeURLError(ValueError):
    """The URL violates the outbound request policy."""


class BlockedAddressError(httpx.ConnectError):
    """A hostname resolved to an address the policy does not allow."""


def ip_is_public(address: str) -> bool:
    """True only for globally routable unicast addresses (handles IPv4-mapped/compatible IPv6)."""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped or ip.sixtofour
        if mapped is not None:
            return ip_is_public(str(mapped))
        if ip.teredo is not None:
            return all(ip_is_public(str(part)) for part in ip.teredo)
    if not ip.is_global:
        return False
    return not (ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local or ip.is_unspecified)


@dataclass(frozen=True)
class NetPolicy:
    """Outbound request policy.

    Attributes:
        allow_http: permit plain ``http`` (development only).
        allow_private: permit non-public addresses (tests/development only; never in production).
        allowed_origins: if non-empty, the only origins (``scheme://host:port``) requests may reach.
        max_response_bytes: cap on response body size.
    """

    allow_http: bool = False
    allow_private: bool = False
    allowed_origins: frozenset[str] = field(default_factory=frozenset)
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES


def origin_of(url: str) -> str:
    """Normalized origin ``scheme://host:port`` of ``url`` (lower-case host, explicit port)."""
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port or (443 if scheme == "https" else 80)
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}:{port}"


def check_url(url: str, policy: NetPolicy) -> str:
    """Validate ``url`` against ``policy`` and return it unchanged.

    Raises:
        UnsafeURLError: with a user-presentable reason.
    """
    if not url or len(url) > MAX_URL_LENGTH:
        raise UnsafeURLError(f"URL must be 1-{MAX_URL_LENGTH} characters")
    if any(ch.isspace() or ord(ch) < 32 for ch in url):
        raise UnsafeURLError("URL must not contain whitespace or control characters")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise UnsafeURLError(f"malformed URL: {exc}") from exc
    allowed = {"https", "http"} if policy.allow_http else {"https"}
    if parsed.scheme.lower() not in allowed:
        raise UnsafeURLError("only https:// URLs are allowed")
    if parsed.username or parsed.password:
        raise UnsafeURLError("URLs must not contain credentials; use the auth header field instead")
    host = (parsed.hostname or "").rstrip(".")
    if not host:
        raise UnsafeURLError("URL has no host")
    if port is not None and not 1 <= port <= 65535:
        raise UnsafeURLError("invalid port")
    if not policy.allow_private:
        literal: str | None = None
        try:
            literal = str(ipaddress.ip_address(host))
        except ValueError:
            literal = None
        if literal is not None and not ip_is_public(literal):
            raise UnsafeURLError("URL points to a non-public IP address")
        if host.lower() in {"localhost", "localhost.localdomain"} or host.lower().endswith(
            (".localhost", ".local", ".internal", ".lan", ".home.arpa")
        ):
            raise UnsafeURLError("URL points to a local hostname")
    if policy.allowed_origins and origin_of(url) not in policy.allowed_origins:
        raise UnsafeURLError("URL is not on a verified origin for this scan")
    return url


class GuardedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Resolves hostnames itself and only connects to policy-approved addresses."""

    def __init__(self, policy: NetPolicy, inner: httpcore.AsyncNetworkBackend | None = None) -> None:
        self.policy = policy
        self.inner = inner or httpcore.AnyIOBackend()

    async def resolve(self, host: str, port: int) -> list[str]:
        """Resolve ``host`` and return addresses, raising if any is not allowed."""
        try:
            infos = await anyio.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise httpx.ConnectError(f"could not resolve {host!r}: {exc}") from exc
        addresses = list(dict.fromkeys(str(info[4][0]) for info in infos))
        if not addresses:
            raise httpx.ConnectError(f"no addresses for {host!r}")
        if not self.policy.allow_private:
            blocked = [a for a in addresses if not ip_is_public(a)]
            if blocked:
                raise BlockedAddressError(f"{host!r} resolves to a non-public address; request blocked")
        return addresses

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 - httpcore backend interface
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        """Connect to the first validated address for ``host``."""
        addresses = await self.resolve(host, port)
        last_error: Exception | None = None
        for address in addresses:
            try:
                return await self.inner.connect_tcp(
                    address, port, timeout=timeout, local_address=local_address, socket_options=socket_options
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout, OSError) as exc:
                last_error = exc
        raise httpx.ConnectError(f"could not connect to {host!r}: {last_error}")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109 - httpcore backend interface
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        """Unix sockets are never allowed for outbound scans."""
        raise BlockedAddressError("unix sockets are not allowed")

    async def sleep(self, seconds: float) -> None:
        """Delegate sleeping to the inner backend."""
        await self.inner.sleep(seconds)


class _LimitedStream(httpx.AsyncByteStream):
    def __init__(self, stream: httpx.AsyncByteStream, limit: int) -> None:
        self._stream = stream
        self._limit = limit

    async def __aiter__(self) -> AsyncIterator[bytes]:
        received = 0
        async for chunk in self._stream:
            received += len(chunk)
            if received > self._limit:
                raise httpx.ReadError(f"response exceeded {self._limit} bytes; aborted")
            yield chunk

    async def aclose(self) -> None:
        await self._stream.aclose()


class SafeTransport(httpx.AsyncHTTPTransport):
    """``httpx`` transport enforcing :class:`NetPolicy` on every request."""

    def __init__(self, policy: NetPolicy, *, verify: ssl.SSLContext | bool = True) -> None:
        super().__init__(verify=verify, trust_env=False, retries=0)
        self.policy = policy
        context = httpx.create_ssl_context(verify=verify, trust_env=False)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=context,
            max_connections=20,
            max_keepalive_connections=10,
            keepalive_expiry=5.0,
            network_backend=GuardedNetworkBackend(policy),
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Validate the URL, perform the request, and cap the response size."""
        try:
            check_url(str(request.url), self.policy)
        except UnsafeURLError as exc:
            raise BlockedAddressError(str(exc), request=request) from exc
        response = await super().handle_async_request(request)
        stream = typing.cast(httpx.AsyncByteStream, response.stream)
        response.stream = _LimitedStream(stream, self.policy.max_response_bytes)
        return response


def safe_client(policy: NetPolicy, *, timeout: float = 20.0) -> httpx.AsyncClient:
    """An ``httpx.AsyncClient`` that never follows redirects and enforces ``policy``."""
    return httpx.AsyncClient(
        transport=SafeTransport(policy),
        timeout=httpx.Timeout(timeout, connect=10.0),
        follow_redirects=False,
        trust_env=False,
        headers={"User-Agent": "AgentGuard-Scanner/1.0 (+https://github.com/PiyushDas-2004/agentguard)"},
    )
