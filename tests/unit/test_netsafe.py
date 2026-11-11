"""SSRF guard: URL validation, address classification and connect-time enforcement."""

from __future__ import annotations

import httpx
import pytest

from agentguard.netsafe import (
    BlockedAddressError,
    GuardedNetworkBackend,
    NetPolicy,
    SafeTransport,
    UnsafeURLError,
    check_url,
    ip_is_public,
    origin_of,
    safe_client,
)

STRICT = NetPolicy()


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",
        "100.64.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "2002:7f00:1::",
        "64:ff9b::7f00:1",
        "fd00:ec2::254",
        "fec0::1",
        "not-an-ip",
    ],
)
def test_non_public_addresses_are_rejected(address: str) -> None:
    assert ip_is_public(address) is False


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"])
def test_public_addresses_are_accepted(address: str) -> None:
    assert ip_is_public(address) is True


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/",  # plain http
        "ftp://example.com/",
        "file:///etc/passwd",
        "gopher://example.com/",
        "https://user:pw@example.com/",  # embedded credentials
        "https://127.0.0.1/",
        "https://[::1]/",
        "https://169.254.169.254/latest/meta-data/",
        "https://[::ffff:7f00:1]/",
        "https://localhost/",
        "https://api.localhost/",
        "https://printer.local/",
        "https://metadata.google.internal/",
        "https://example.com/\r\nX: y",
        "https://exa mple.com/",
        "https:///nohost",
        "https://example.com:99999/",
        "",
        "https://example.com/" + "a" * 3000,
    ],
)
def test_unsafe_urls_are_refused(url: str) -> None:
    with pytest.raises(UnsafeURLError):
        check_url(url, STRICT)


def test_public_https_url_passes_and_origin_is_normalized() -> None:
    assert check_url("https://Agent.Example.com/chat", STRICT) == "https://Agent.Example.com/chat"
    assert origin_of("https://Agent.Example.com./chat?x=1") == "https://agent.example.com:443"
    assert origin_of("http://[2001:db8::1]:8080/") == "http://[2001:db8::1]:8080"


def test_origin_pinning() -> None:
    policy = NetPolicy(allowed_origins=frozenset({"https://agent.example.com:443"}))
    assert check_url("https://agent.example.com/v1/chat", policy)
    with pytest.raises(UnsafeURLError, match="verified origin"):
        check_url("https://evil.example.net/", policy)
    with pytest.raises(UnsafeURLError, match="verified origin"):
        check_url("https://agent.example.com:8443/", policy)


def test_development_policy_allows_local_http() -> None:
    assert check_url("http://127.0.0.1:8080/chat", NetPolicy(allow_http=True, allow_private=True))


@pytest.mark.parametrize("host", ["127.0.0.1", "2130706433", "0x7f000001", "127.1", "localhost", "[::1]"])
async def test_connect_time_guard_blocks_obfuscated_loopback(host: str) -> None:
    """Hostnames are resolved by the guard itself, so numeric tricks and DNS answers are both checked."""
    async with safe_client(NetPolicy(allow_http=True), timeout=3) as client:
        with pytest.raises(httpx.ConnectError):
            await client.get(f"http://{host}:9/")


async def test_dns_answers_are_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    """A public-looking name that resolves to a private address (DNS rebinding) is blocked."""

    async def fake_getaddrinfo(host: str, port: int, **_: object) -> list[tuple[object, ...]]:
        return [(2, 1, 6, "", ("10.0.0.7", port)), (2, 1, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr("agentguard.netsafe.anyio.getaddrinfo", fake_getaddrinfo)
    backend = GuardedNetworkBackend(NetPolicy())
    with pytest.raises(BlockedAddressError):
        await backend.resolve("rebind.example.com", 443)


async def test_unix_sockets_are_never_allowed() -> None:
    with pytest.raises(BlockedAddressError):
        await GuardedNetworkBackend(NetPolicy(allow_private=True)).connect_unix_socket("/var/run/docker.sock")


async def test_redirects_are_not_followed_and_body_is_capped() -> None:
    import asyncio

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request = await reader.readuntil(b"\r\n\r\n")
        if request.startswith(b"GET /redirect"):
            writer.write(b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\nContent-Length: 0\r\n\r\n")
        else:
            body = b"x" * 5000
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    policy = NetPolicy(allow_http=True, allow_private=True, max_response_bytes=1000)
    try:
        async with httpx.AsyncClient(transport=SafeTransport(policy), follow_redirects=False) as client:
            redirect = await client.get(f"http://127.0.0.1:{port}/redirect")
            assert redirect.status_code == 302  # surfaced, never followed
            with pytest.raises(httpx.HTTPError):
                await client.get(f"http://127.0.0.1:{port}/big")
    finally:
        server.close()
        await server.wait_closed()


async def test_compressed_responses_are_refused() -> None:
    """The size cap counts wire bytes, so a gzip bomb must never be decoded."""
    import asyncio
    import gzip

    bomb = gzip.compress(b"\0" * 5_000_000)
    seen: list[bytes] = []

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        seen.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n" % len(bomb) + bomb)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        async with safe_client(NetPolicy(allow_http=True, allow_private=True), timeout=5) as client:
            with pytest.raises(httpx.RemoteProtocolError, match="compressed"):
                await client.get(f"http://127.0.0.1:{port}/")
    finally:
        server.close()
        await server.wait_closed()
    assert b"accept-encoding: identity" in seen[0].lower()
