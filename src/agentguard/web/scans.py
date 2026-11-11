"""Build and run a hosted scan safely.

* Only ``http`` and ``openai_compat`` targets (no code execution: python/langchain/mcp are refused).
* The target's transport is SSRF-safe and **pinned to the verified origin**.
* Each scan runs in an isolated temporary workspace (its own SQLite + transcripts), deleted after.
* Secrets (Gemini key, agent auth header) live only in this process' memory for the scan's
  duration and are redacted from any stored error text.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from agentguard.attacks.loader import load_cases
from agentguard.bundled import resolve_bundled
from agentguard.config.loader import parse_config
from agentguard.config.models import AgentGuardConfig, ResponseMapping
from agentguard.core.runner import Runner, RunOptions
from agentguard.core.types import AttackCase, AttackCategory, InjectionVector, RunResult
from agentguard.netsafe import NetPolicy, SafeTransport, check_url, origin_of
from agentguard.storage.db import Database
from agentguard.targets.base import BaseTarget
from agentguard.targets.http import HTTPTarget
from agentguard.targets.openai_compat import OpenAICompatibleTarget
from agentguard.web.models import Target
from agentguard.web.settings import WebSettings

__all__ = [
    "HOSTED_CATEGORIES",
    "REQUEST_PRESETS",
    "ScanRequest",
    "ScanSecrets",
    "build_target",
    "run_hosted_scan",
    "select_cases",
]

REQUEST_PRESETS: dict[str, str] = {
    "message": '{"message": {{ message | tojson }}}',
    "messages": '{"messages": {{ messages | tojson }}}',
    "message_and_history": '{"message": {{ message | tojson }}, "history": {{ messages[:-1] | tojson }}}',
}
TARGET_MAX_RESPONSE_BYTES = 256 * 1024
TRANSFORMS = ["base64", "rot13", "leetspeak", "homoglyph", "zero_width", "wrapper_roleplay"]

# Black-box HTTP agents cannot be given AgentGuard's mock tools/memory/corpus, so only categories
# measurable from the conversation itself are offered. OpenAI-compatible targets run tools through
# AgentGuard's sandbox, so every category applies.
HTTP_CATEGORIES: tuple[AttackCategory, ...] = (
    AttackCategory.PI_DIRECT,
    AttackCategory.JAILBREAK,
    AttackCategory.SYS_PROMPT_LEAK,
    AttackCategory.DATA_EXFIL,
    AttackCategory.INSECURE_OUTPUT,
    AttackCategory.DENIAL_OF_WALLET,
    AttackCategory.PKG_HALLUCINATION,
    AttackCategory.OVER_REFUSAL,
    AttackCategory.EXCESSIVE_AGENCY,
)
HOSTED_CATEGORIES: dict[str, tuple[AttackCategory, ...]] = {
    "http": HTTP_CATEGORIES,
    "openai_compat": tuple(AttackCategory),
}


@dataclass(frozen=True)
class ScanSecrets:
    """In-memory-only secrets for one scan."""

    gemini_api_key: str | None = field(default=None, repr=False)
    auth_header_value: str | None = field(default=None, repr=False)
    auth_header_name: str = "Authorization"  # not secret, but only meaningful together with the value

    def values(self) -> list[str]:
        """All secret strings (for redaction)."""
        return [v for v in (self.gemini_api_key, self.auth_header_value) if v]


@dataclass(frozen=True)
class ScanRequest:
    """Validated scan parameters."""

    categories: tuple[AttackCategory, ...]
    trials: int
    mutations: bool
    judge: str  # deterministic | gemini
    judge_model: str = ""
    seed: int = 1337


def _datasets() -> list[Path]:
    paths = [resolve_bundled("datasets/attacks"), resolve_bundled("datasets/benign")]
    return [p for p in paths if p is not None]


def select_cases(target: Target, categories: tuple[AttackCategory, ...], limit: int) -> list[AttackCase]:
    """Cases runnable against ``target`` for ``categories`` (capped at ``limit``)."""
    allowed = set(HOSTED_CATEGORIES.get(target.kind, ()))
    wanted = [c for c in categories if c in allowed]
    cases = [c for c in load_cases(_datasets(), strict=True).cases if c.category in wanted]
    if target.kind == "http":
        cases = [c for c in cases if c.vector == InjectionVector.user_message and len(c.sessions) == 1]
        if not target.tool_calls_path:
            cases = [c for c in cases if c.category != AttackCategory.EXCESSIVE_AGENCY]
    return sorted(cases, key=lambda c: c.id)[:limit]


def target_policy(target: Target, settings: WebSettings) -> NetPolicy:
    """Outbound policy for a scan: only the target's verified origin is reachable."""
    return NetPolicy(
        allow_http=settings.allow_http_targets,
        allow_private=settings.allow_private_targets,
        allowed_origins=frozenset({origin_of(target.url)}),
        max_response_bytes=TARGET_MAX_RESPONSE_BYTES,
    )


def build_target(target: Target, request: ScanRequest, secrets: ScanSecrets, settings: WebSettings) -> BaseTarget:
    """Instantiate the (SSRF-safe, origin-pinned) adapter for ``target``.

    Raises:
        ValueError: unsupported target kind or a URL that violates policy.
    """
    policy = target_policy(target, settings)
    check_url(target.url, policy)
    transport = SafeTransport(policy)
    timeout = settings.request_timeout_seconds
    if target.kind == "http":
        headers = {}
        if secrets.auth_header_value:
            headers[secrets.auth_header_name] = secrets.auth_header_value
        return HTTPTarget(
            target.url,
            headers=headers,
            request_template=target.request_template or REQUEST_PRESETS["message"],
            mapping=ResponseMapping(text=target.text_path or "$.reply", tool_calls=target.tool_calls_path or None),
            timeout=timeout,
            transport=transport,
            interpolate_headers=False,
        )
    if target.kind == "openai_compat":
        return OpenAICompatibleTarget(
            target.url,
            target.model or "default",
            api_key=secrets.auth_header_value,
            timeout=timeout,
            transport=transport,
        )
    raise ValueError(f"target kind {target.kind!r} is not allowed in the hosted service")


def run_config(target: Target, request: ScanRequest, settings: WebSettings, workspace: Path) -> AgentGuardConfig:
    """AgentGuard configuration for a hosted scan."""
    return parse_config(
        {
            "run": {
                "name": f"hosted-{target.name}"[:80],
                "trials_per_case": request.trials,
                "concurrency": 2,
                "seed": request.seed,
                "timeout_seconds": settings.request_timeout_seconds,
                "rate_limit_per_second": settings.target_requests_per_second,
                "max_retries": 2,
                "max_output_chars": 8_000,
            },
            "target": {
                "type": target.kind,
                "url": target.url,
                "model": target.model or None,
                "known_secrets": [target.canary],
            },
            "suites": {
                "security": {
                    "datasets": [str(p) for p in _datasets()],
                    "mutations": {"enabled": request.mutations, "per_case": 2, "transforms": TRANSFORMS},
                }
            },
            "judge": {
                "provider": "gemini" if request.judge == "gemini" else "mock",
                "model": request.judge_model or None,
            },
            "reports": {"formats": [], "embed_trials_per_case": 1},
            "storage": {"db_path": str(workspace / "scan.db"), "transcripts_dir": str(workspace / "tr")},
        }
    )


async def run_hosted_scan(
    target: Target,
    request: ScanRequest,
    secrets: ScanSecrets,
    settings: WebSettings,
    *,
    progress: Callable[[int, int], None] | None = None,
    target_override: BaseTarget | None = None,
) -> RunResult:
    """Run one hosted scan in an isolated workspace and return its result."""
    cases = select_cases(target, request.categories, settings.max_cases_per_scan)
    if not cases:
        raise ValueError("no test cases apply to this target with the selected categories")
    workspace = Path(tempfile.mkdtemp(prefix="agentguard-scan-"))
    try:
        config = run_config(target, request, settings, workspace)
        if request.judge == "gemini":
            from pydantic import SecretStr

            config = config.model_copy(
                update={"judge": config.judge.model_copy(update={"api_key": SecretStr(secrets.gemini_api_key or "")})}
            )
        adapter = target_override or build_target(target, request, secrets, settings)
        options = RunOptions(
            suite="security",
            case_ids=[c.id for c in cases],
            trials=request.trials,
            offline=request.judge != "gemini",
            progress=progress,
        )
        runner = Runner(
            config,
            options,
            base_dir=workspace,
            target=adapter,
            database=Database(workspace / "scan.db"),
        )
        return await runner.run()
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
