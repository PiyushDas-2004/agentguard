"""Pydantic schema for ``agentguard`` YAML configuration files."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from agentguard.core.types import AttackCategory

__all__ = [
    "AdaptiveConfig",
    "AgentGuardConfig",
    "JudgeConfig",
    "LLMConfig",
    "MutationConfig",
    "QualitySuiteConfig",
    "ReportsConfig",
    "ResponseMapping",
    "RunConfig",
    "SecuritySuiteConfig",
    "StorageConfig",
    "SuitesConfig",
    "TargetConfig",
]

ALL_TRANSFORMS = (
    "base64",
    "rot13",
    "leetspeak",
    "homoglyph",
    "zero_width",
    "token_split",
    "wrapper_roleplay",
    "wrapper_json",
    "translate_mock",
    "paraphrase",
)


Backend = Literal["builtin", "ragas", "deepeval"]
ReportFormat = Literal["html", "json", "sarif", "junit", "markdown"]


def _default_backends() -> list[Backend]:
    return ["builtin"]


def _default_formats() -> list[ReportFormat]:
    return ["html", "json", "sarif", "junit", "markdown"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LLMConfig(_Strict):
    """LLM provider settings.

    Attributes:
        provider: ``mock``, ``anthropic``, ``openai``, ``ollama`` or ``litellm``.
        profile: MockLLM profile (``vulnerable`` / ``naive``).
        model: provider model id (live providers).
        temperature: sampling temperature for live providers.
        api_base: override base URL (e.g. Ollama).
        injection_compliance: MockLLM probability of obeying injected instructions.
    """

    provider: Literal["mock", "anthropic", "openai", "ollama", "litellm", "gemini"] = "mock"
    profile: str = "vulnerable"
    model: str | None = None
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    api_base: str | None = None
    injection_compliance: float = Field(default=0.9, ge=0.0, le=1.0)
    api_key: SecretStr | None = Field(default=None, exclude=True, repr=False)


class ResponseMapping(_Strict):
    """JSONPath expressions that extract data from an HTTP target's JSON response."""

    text: str = "$.text"
    tool_calls: str | None = None
    tool_name_field: str = "name"
    tool_args_field: str = "arguments"


class TargetConfig(_Strict):
    """How to reach the system under test."""

    type: str = Field(description="python_callable | http | openai_compat | langchain | mcp | plugin name")
    name: str | None = None
    path: str | None = None
    url: str | None = None
    method: Literal["GET", "POST", "PUT", "PATCH"] = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    request_template: str | None = None
    response_mapping: ResponseMapping = Field(default_factory=ResponseMapping)
    model: str | None = None
    api_key_env: str | None = None
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    system_prompt: str | None = None
    known_secrets: list[str] = Field(default_factory=list)
    max_tool_steps: int = Field(default=8, ge=1, le=100)
    options: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _required_fields(self) -> TargetConfig:
        needs = {
            "python_callable": "path",
            "http": "url",
            "openai_compat": "url",
            "langchain": "path",
            "mcp": "command",
        }
        field_name = needs.get(self.type)
        if field_name and not getattr(self, field_name):
            raise ValueError(f"target type '{self.type}' requires '{field_name}'")
        return self


class MutationConfig(_Strict):
    """Mutation engine settings."""

    enabled: bool = False
    per_case: int = Field(default=3, ge=0, le=20)
    transforms: list[str] = Field(default_factory=lambda: list(ALL_TRANSFORMS[:9]))

    @field_validator("transforms")
    @classmethod
    def _known(cls, value: list[str]) -> list[str]:
        unknown = [t for t in value if t not in ALL_TRANSFORMS]
        if unknown:
            raise ValueError(f"unknown transform(s) {unknown}; choose from {list(ALL_TRANSFORMS)}")
        return value


class AdaptiveConfig(_Strict):
    """Adaptive (PAIR-style) attacker settings."""

    enabled: bool = False
    max_turns: int = Field(default=5, ge=1, le=20)
    attacker: LLMConfig = Field(default_factory=lambda: LLMConfig(provider="mock", profile="attacker"))


class SecuritySuiteConfig(_Strict):
    """Security suite selection."""

    enabled: bool = True
    categories: Literal["all"] | list[AttackCategory] = "all"
    datasets: list[str] = Field(default_factory=lambda: ["datasets/attacks", "datasets/benign"])
    cases: list[str] = Field(default_factory=list)
    mutations: MutationConfig = Field(default_factory=MutationConfig)
    adaptive: AdaptiveConfig = Field(default_factory=AdaptiveConfig)


class QualitySuiteConfig(_Strict):
    """Quality suite selection."""

    enabled: bool = True
    tasks: str | None = None
    rag: str | None = None
    backends: list[Backend] = Field(default_factory=_default_backends)
    trials_per_task: int | None = Field(default=None, ge=1, le=100)


class SuitesConfig(_Strict):
    """Which suites to run."""

    security: SecuritySuiteConfig = Field(default_factory=SecuritySuiteConfig)
    quality: QualitySuiteConfig | None = None


class JudgeConfig(_Strict):
    """Judge settings."""

    provider: Literal["mock", "anthropic", "openai", "ollama", "litellm", "gemini"] = "mock"
    model: str | None = None
    ensemble: bool = False
    second_provider: Literal["mock", "anthropic", "openai", "ollama", "litellm", "gemini"] | None = None
    second_model: str | None = None
    max_repair_retries: int = Field(default=2, ge=0, le=5)
    plugin: str | None = Field(default=None, description="name of an agentguard.judges entry-point judge")
    api_key: SecretStr | None = Field(default=None, exclude=True, repr=False)
    plugin_options: dict[str, Any] = Field(default_factory=dict)


class ReportsConfig(_Strict):
    """Report output settings."""

    formats: list[ReportFormat] = Field(default_factory=_default_formats)
    out_dir: str = "reports/"
    embed_trials_per_case: int = Field(default=3, ge=0, le=50)


class StorageConfig(_Strict):
    """Result persistence settings."""

    db_path: str = ".agentguard/agentguard.db"
    transcripts_dir: str = ".agentguard/transcripts"


class RunConfig(_Strict):
    """Run-wide execution settings."""

    name: str = "agentguard-run"
    trials_per_case: int = Field(default=5, ge=1, le=1000)
    concurrency: int = Field(default=8, ge=1, le=512)
    seed: int = 1337
    timeout_seconds: float = Field(default=30.0, gt=0, le=3600)
    max_cost_usd: float | None = Field(default=None, ge=0)
    fail_threshold_risk: float = Field(default=40.0, ge=0, le=100)
    status_threshold: float = Field(default=0.10, gt=0, lt=1)
    rate_limit_per_second: float = Field(default=0.0, ge=0)
    max_retries: int = Field(default=3, ge=0, le=10)
    retry_base_seconds: float = Field(default=0.5, ge=0)
    max_error_fraction: float = Field(default=0.20, ge=0, le=1)
    max_output_chars: int = Field(default=200_000, ge=1000)
    strict_datasets: bool = False
    otel: bool = False


class AgentGuardConfig(_Strict):
    """Root of an AgentGuard configuration file."""

    version: Literal[1] = 1
    run: RunConfig = Field(default_factory=RunConfig)
    target: TargetConfig
    policy: str | dict[str, Any] | None = None
    suites: SuitesConfig = Field(default_factory=SuitesConfig)
    judge: JudgeConfig = Field(default_factory=JudgeConfig)
    reports: ReportsConfig = Field(default_factory=ReportsConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    plugins: list[str] = Field(default_factory=list)
