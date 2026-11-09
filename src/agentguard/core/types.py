"""Core data models shared across AgentGuard (Part E of the specification).

Every model is a Pydantic v2 model that round-trips losslessly through JSON. Enumerations are
string-valued (``Severity`` additionally exposes its numeric weight) so serialized output stays
human readable.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

__all__ = [
    "SEVERITY_WEIGHTS",
    "AttackCase",
    "AttackCategory",
    "CaseResult",
    "CaseStatus",
    "CategoryScorecard",
    "ErrorInfo",
    "EvidenceSpan",
    "InjectionVector",
    "Objective",
    "ObjectiveType",
    "OwaspCoverageRow",
    "PerformanceReport",
    "Poison",
    "QualityReport",
    "Role",
    "RunResult",
    "Severity",
    "TargetInfo",
    "ToolCall",
    "Transcript",
    "TranscriptTurn",
    "Trial",
    "TrialSample",
    "Turn",
    "Verdict",
    "utcnow",
]


def utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


class _Model(BaseModel):
    """Base model: forbid unknown fields so dataset typos surface as validation errors."""

    model_config = ConfigDict(extra="forbid", use_enum_values=False, validate_assignment=False)


class Severity(StrEnum):
    """Severity of an attack case. The numeric weight is exposed by :attr:`weight`."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def weight(self) -> int:
        """Numeric risk weight used by the scoring formulas (critical=10 ... info=0)."""
        return SEVERITY_WEIGHTS[self]


SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.critical: 10,
    Severity.high: 7,
    Severity.medium: 4,
    Severity.low: 1,
    Severity.info: 0,
}


class AttackCategory(StrEnum):
    """Attack / evaluation categories."""

    PI_DIRECT = "PI_DIRECT"
    PI_INDIRECT = "PI_INDIRECT"
    JAILBREAK = "JAILBREAK"
    SYS_PROMPT_LEAK = "SYS_PROMPT_LEAK"
    DATA_EXFIL = "DATA_EXFIL"
    PII_LEAK = "PII_LEAK"
    EXCESSIVE_AGENCY = "EXCESSIVE_AGENCY"
    INSECURE_OUTPUT = "INSECURE_OUTPUT"
    MEMORY_POISON = "MEMORY_POISON"
    RAG_POISON = "RAG_POISON"
    DENIAL_OF_WALLET = "DENIAL_OF_WALLET"
    PKG_HALLUCINATION = "PKG_HALLUCINATION"
    OVER_REFUSAL = "OVER_REFUSAL"


class InjectionVector(StrEnum):
    """Where an attack payload is delivered."""

    user_message = "user_message"
    system_context = "system_context"
    rag_document = "rag_document"
    tool_output = "tool_output"
    file_content = "file_content"
    email_body = "email_body"
    web_page = "web_page"
    memory = "memory"


class Role(StrEnum):
    """Conversation roles."""

    system = "system"
    user = "user"
    assistant = "assistant"
    tool = "tool"


class CaseStatus(StrEnum):
    """Statistical outcome of a case."""

    passed = "pass"
    failed = "fail"
    inconclusive = "inconclusive"


class Turn(_Model):
    """One scripted conversation turn of an attack case.

    ``content`` may contain the template variables ``{{CANARY}}``, ``{{ATTACKER_ACCOUNT}}`` and
    ``{{EXFIL_URL}}`` which are rendered per trial. ``session`` groups turns into separate
    sessions (used by cross-session memory poisoning).
    """

    role: Literal["user", "assistant"] = "user"
    content: str
    session: int = Field(default=1, ge=1, le=10)


class Poison(_Model):
    """A payload planted into a non-user injection vector before the conversation starts.

    Attributes:
        vector: where the payload is planted.
        content: the payload text (template variables allowed).
        location: vector-specific address: a file path, URL, e-mail subject, memory key,
            RAG document id, or tool name.
        corpus_doc: optional name of a poisoned document in ``datasets/rag_corpus/poisoned``
            to add to the retrieval index instead of (or in addition to) ``content``.
    """

    vector: InjectionVector
    content: str = ""
    location: str | None = None
    corpus_doc: str | None = None

    @model_validator(mode="after")
    def _non_empty(self) -> Poison:
        if not self.content and not self.corpus_doc:
            raise ValueError("poison needs either 'content' or 'corpus_doc'")
        if self.vector == InjectionVector.user_message:
            raise ValueError("poison vector cannot be user_message; put the payload in 'turns'")
        return self


class ObjectiveType(StrEnum):
    """Machine-checkable attacker goals."""

    canary_leak = "canary_leak"
    tool_call = "tool_call"
    output_regex = "output_regex"
    system_prompt_leak = "system_prompt_leak"
    pii_disclosure = "pii_disclosure"
    resource_exhaustion = "resource_exhaustion"
    package_hallucination = "package_hallucination"
    answered = "answered"


class Objective(_Model):
    """The attacker's machine-checkable success condition.

    Attributes:
        type: the kind of check.
        description: human readable goal.
        tool: tool name for ``tool_call`` objectives.
        args_match: per-argument regular expressions that must all match (``tool_call``).
        pattern: regular expression for ``output_regex`` objectives.
    """

    type: ObjectiveType
    description: str
    tool: str | None = None
    args_match: dict[str, str] = Field(default_factory=dict)
    pattern: str | None = None

    @model_validator(mode="after")
    def _check_fields(self) -> Objective:
        if self.type == ObjectiveType.tool_call and not self.tool:
            raise ValueError("tool_call objectives require 'tool'")
        if self.type == ObjectiveType.output_regex and not self.pattern:
            raise ValueError("output_regex objectives require 'pattern'")
        for rx in [*self.args_match.values(), *([self.pattern] if self.pattern else [])]:
            try:
                re.compile(rx)
            except re.error as exc:
                raise ValueError(f"invalid regex {rx!r}: {exc}") from exc
        return self


_CASE_ID = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d{3}$")


class AttackCase(_Model):
    """A single seed attack (or benign) case loaded from a dataset YAML file."""

    id: str
    category: AttackCategory
    title: str = Field(min_length=3)
    description: str = Field(min_length=10)
    severity: Severity
    owasp_llm: list[str] = Field(default_factory=list)
    mitre_atlas: list[str] = Field(default_factory=list)
    vector: InjectionVector
    turns: list[Turn] = Field(min_length=1)
    poison: Poison | None = None
    objective: Objective
    detectors: list[str] = Field(min_length=1)
    mutations_allowed: bool = True
    tags: list[str] = Field(default_factory=list)
    adaptive: bool = False

    @field_validator("id")
    @classmethod
    def _valid_id(cls, value: str) -> str:
        if not _CASE_ID.match(value):
            raise ValueError(f"case id {value!r} must look like 'PI-IND-017'")
        return value

    @model_validator(mode="after")
    def _vector_consistency(self) -> AttackCase:
        if self.vector != InjectionVector.user_message:
            if self.poison is None:
                raise ValueError(f"vector {self.vector.value} requires a 'poison' block")
            if self.poison.vector != self.vector:
                raise ValueError("poison.vector must equal the case vector")
        return self

    @property
    def sessions(self) -> list[int]:
        """Sorted distinct session numbers used by this case's turns."""
        return sorted({t.session for t in self.turns})


class ToolCall(_Model):
    """A recorded tool invocation (or approval request) made by the target."""

    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utcnow)
    allowed: bool = True
    approval_required: bool = False
    approved: bool | None = None
    executed: bool = True
    is_approval_request: bool = False
    policy_violations: list[str] = Field(default_factory=list)
    result_preview: str = ""
    turn_index: int = 0
    session: int = 1


class TranscriptTurn(_Model):
    """One message in a trial transcript with its accounting metadata."""

    index: int
    role: Role
    content: str
    session: int = 1
    model: str | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    truncated: bool = False


class Transcript(_Model):
    """Ordered turns and tool calls of one trial plus aggregate accounting."""

    turns: list[TranscriptTurn] = Field(default_factory=list)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    model: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def tokens_in(self) -> int:
        """Total prompt tokens across all turns."""
        return sum(t.tokens_in for t in self.turns)

    @property
    def tokens_out(self) -> int:
        """Total completion tokens across all turns."""
        return sum(t.tokens_out for t in self.turns)

    @property
    def cost_usd(self) -> float:
        """Total cost in USD across all turns."""
        return sum(t.cost_usd for t in self.turns)

    @property
    def latency_ms(self) -> float:
        """Total latency in milliseconds across all turns."""
        return sum(t.latency_ms for t in self.turns)

    def assistant_text(self) -> str:
        """Concatenate every assistant message (what the user would see)."""
        return "\n".join(t.content for t in self.turns if t.role == Role.assistant)

    def user_text(self) -> str:
        """Concatenate every user message (attacker-controlled input)."""
        return "\n".join(t.content for t in self.turns if t.role == Role.user)


class ErrorInfo(_Model):
    """Structured error attached to a trial that could not complete."""

    type: str
    message: str
    retryable: bool = False


class Trial(_Model):
    """One execution of a case (optionally mutated) against the target."""

    run_id: str
    case_id: str
    trial_index: int = Field(ge=0)
    seed: int
    mutation_id: str | None = None
    transcript: Transcript = Field(default_factory=Transcript)
    error: ErrorInfo | None = None
    started_at: datetime = Field(default_factory=utcnow)
    ended_at: datetime | None = None
    violated: bool | None = None
    inconclusive: bool = False
    objective_met: bool | None = None

    @property
    def trial_id(self) -> str:
        """Stable identifier for this trial within its run."""
        return f"{self.run_id}:{self.case_id}:{self.mutation_id or 'seed'}:{self.trial_index}"


class EvidenceSpan(_Model):
    """A highlighted span of transcript text supporting a verdict.

    ``turn_index`` is ``-1`` when the evidence is a tool call rather than message text.
    """

    turn_index: int
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    text: str
    reason: str

    @model_validator(mode="after")
    def _ordered(self) -> EvidenceSpan:
        if self.end < self.start:
            raise ValueError("evidence span end must be >= start")
        return self


class Verdict(_Model):
    """A detector or judge decision about one trial."""

    detector_id: str
    trial_id: str
    violated: bool
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[EvidenceSpan] = Field(default_factory=list)
    explanation: str = ""
    inconclusive: bool = False


class TrialSample(_Model):
    """A trial embedded in reports (transcript + verdicts) for the transcript viewer."""

    trial_id: str
    trial_index: int
    mutation_id: str | None = None
    violated: bool | None = None
    error: ErrorInfo | None = None
    transcript: Transcript
    verdicts: list[Verdict] = Field(default_factory=list)


class CaseResult(_Model):
    """Aggregated statistics for one case across all of its trials."""

    case_id: str
    category: AttackCategory
    title: str = ""
    owasp_llm: list[str] = Field(default_factory=list)
    n_trials: int = Field(ge=0)
    n_errors: int = Field(ge=0)
    n_inconclusive: int = Field(default=0, ge=0)
    n_violations: int = Field(ge=0)
    violation_rate: float = Field(ge=0.0, le=1.0)
    ci_low: float = Field(ge=0.0, le=1.0)
    ci_high: float = Field(ge=0.0, le=1.0)
    severity: Severity
    risk_contribution: float = Field(ge=0.0)
    status: CaseStatus
    seed_violation_rate: float | None = None
    mutated_violation_rate: float | None = None
    mutation_rates: dict[str, float] = Field(default_factory=dict)
    objective_success_rate: float | None = None
    detectors_triggered: dict[str, int] = Field(default_factory=dict)
    samples: list[TrialSample] = Field(default_factory=list)


class CategoryScorecard(_Model):
    """Per-category roll-up of case results."""

    category: AttackCategory
    n_cases: int
    n_pass: int
    n_fail: int
    n_inconclusive: int
    n_trials: int
    n_violations: int
    violation_rate: float
    ci_low: float
    ci_high: float
    risk: float


class OwaspCoverageRow(_Model):
    """One row of the OWASP LLM Top 10 (2025) coverage matrix."""

    owasp_id: str
    title: str
    n_cases: int
    n_pass: int
    n_fail: int
    n_inconclusive: int


class PerformanceReport(_Model):
    """Latency, token, cost and error statistics."""

    n_calls: int = 0
    latency_p50_ms: float = 0.0
    latency_p95_ms: float = 0.0
    latency_p99_ms: float = 0.0
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    cost_per_task_usd: float = 0.0
    error_rate: float = 0.0


class QualityReport(_Model):
    """Quality-suite metrics (task trajectories, consistency, RAG metrics, backends)."""

    n_tasks: int = 0
    task_success_rate: float | None = None
    trajectory: dict[str, float] = Field(default_factory=dict)
    consistency: dict[str, float] = Field(default_factory=dict)
    rag: dict[str, float] = Field(default_factory=dict)
    backends: dict[str, dict[str, float]] = Field(default_factory=dict)
    backend_messages: list[str] = Field(default_factory=list)
    per_task: list[dict[str, Any]] = Field(default_factory=list)
    per_question: list[dict[str, Any]] = Field(default_factory=list)
    performance: PerformanceReport = Field(default_factory=PerformanceReport)


class TargetInfo(_Model):
    """Description of the evaluated target."""

    type: str
    name: str
    details: dict[str, Any] = Field(default_factory=dict)


class RunResult(_Model):
    """Complete result of an AgentGuard run (serialized as the JSON report)."""

    run_id: str
    name: str
    started_at: datetime
    ended_at: datetime | None = None
    duration_s: float = 0.0
    partial: bool = False
    abort_reason: str | None = None
    target: TargetInfo
    config_hash: str
    git_sha: str | None = None
    agentguard_version: str
    seed: int
    trials_per_case: int
    fail_threshold_risk: float
    status_threshold: float = 0.10
    cases: list[CaseResult] = Field(default_factory=list)
    categories: list[CategoryScorecard] = Field(default_factory=list)
    quality: QualityReport | None = None
    risk_score: float = 0.0
    grade: str = "A"
    over_refusal_rate: float | None = None
    owasp_coverage: list[OwaspCoverageRow] = Field(default_factory=list)
    total_cost_usd: float = 0.0
    total_trials: int = 0
    total_errors: int = 0
    performance: PerformanceReport = Field(default_factory=PerformanceReport)
    warnings: list[str] = Field(default_factory=list)

    @property
    def passed_threshold(self) -> bool:
        """True when the risk score is at or below the configured fail threshold."""
        return self.risk_score <= self.fail_threshold_risk

    def security_cases(self) -> list[CaseResult]:
        """Case results that count toward the risk score (everything but OVER_REFUSAL)."""
        return [c for c in self.cases if c.category != AttackCategory.OVER_REFUSAL]
