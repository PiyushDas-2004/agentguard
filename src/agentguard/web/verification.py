"""Endpoint ownership verification.

Before AgentGuard sends attack traffic to an origin, the user must prove control of it — otherwise
the hosted scanner could be used to attack third parties. Two methods are accepted:

* **HTTP file**: ``https://<host>[:port]/.well-known/agentguard.txt`` contains the token;
* **DNS TXT**: a TXT record on ``_agentguard.<host>`` equals the token.
"""

from __future__ import annotations

import urllib.parse

from agentguard.netsafe import NetPolicy, UnsafeURLError, check_url, origin_of, safe_client
from agentguard.web.security import constant_time_equals, new_token

__all__ = [
    "VerificationResult",
    "dns_record_name",
    "new_verification_token",
    "verify_dns",
    "verify_http",
    "well_known_url",
]

TOKEN_PREFIX = "agentguard-site-verification="  # noqa: S105 - not a secret
WELL_KNOWN_PATH = "/.well-known/agentguard.txt"


class VerificationResult:
    """Outcome of a verification attempt."""

    def __init__(self, ok: bool, method: str, message: str) -> None:
        self.ok = ok
        self.method = method
        self.message = message


def new_verification_token() -> str:
    """A fresh verification token."""
    return TOKEN_PREFIX + new_token(18)


def well_known_url(url: str) -> str:
    """The well-known verification URL on the same origin as ``url``."""
    parsed = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, WELL_KNOWN_PATH, "", ""))


def dns_record_name(url: str) -> str:
    """The DNS name whose TXT record proves ownership."""
    return "_agentguard." + (urllib.parse.urlsplit(url).hostname or "").rstrip(".")


async def verify_http(url: str, token: str, policy: NetPolicy) -> VerificationResult:
    """Fetch the well-known file through the SSRF-safe client and look for ``token``."""
    target = well_known_url(url)
    pinned = NetPolicy(
        allow_http=policy.allow_http,
        allow_private=policy.allow_private,
        allowed_origins=frozenset({origin_of(url)}),
        max_response_bytes=4096,
    )
    try:
        check_url(target, pinned)
        async with safe_client(pinned, timeout=10.0) as client:
            response = await client.get(target)
            body = (await response.aread()).decode("utf-8", errors="replace")
    except UnsafeURLError as exc:
        return VerificationResult(False, "http", str(exc))
    except Exception as exc:  # network failures are reported, never raised
        return VerificationResult(False, "http", f"could not fetch {target}: {type(exc).__name__}")
    if response.status_code != 200:
        return VerificationResult(False, "http", f"{target} returned HTTP {response.status_code}")
    found = any(constant_time_equals(line.strip(), token) for line in body.splitlines())
    if not found:
        return VerificationResult(False, "http", f"{target} does not contain the verification token")
    return VerificationResult(True, "http", f"verified via {target}")


async def verify_dns(url: str, token: str, *, lifetime: float = 6.0) -> VerificationResult:
    """Look up the TXT record ``_agentguard.<host>`` and compare it with ``token``."""
    import dns.asyncresolver
    import dns.exception

    name = dns_record_name(url)
    try:
        answer = await dns.asyncresolver.resolve(name, "TXT", lifetime=lifetime)
    except dns.exception.DNSException as exc:
        return VerificationResult(False, "dns", f"no TXT record found at {name} ({type(exc).__name__})")
    for record in answer:
        value = b"".join(record.strings).decode("utf-8", errors="replace").strip()
        if constant_time_equals(value, token):
            return VerificationResult(True, "dns", f"verified via TXT {name}")
    return VerificationResult(False, "dns", f"TXT records at {name} do not match the token")
