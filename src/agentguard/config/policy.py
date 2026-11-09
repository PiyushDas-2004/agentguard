"""Security policy: what tools an agent may use, with which arguments, and what data must not leak."""

from __future__ import annotations

import re
import urllib.parse
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from agentguard.core.errors import ConfigError

__all__ = [
    "ApprovalRule",
    "ArgConstraint",
    "Policy",
    "PolicyDecision",
    "PolicyLimits",
    "ProtectedData",
    "domain_allowed",
    "host_of",
    "load_policy",
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def host_of(value: str) -> str:
    """Return the lower-cased host of a URL or the domain of an e-mail address."""
    value = value.strip()
    if "@" in value and "://" not in value:
        return value.rsplit("@", 1)[1].lower().strip(">")
    parsed = urllib.parse.urlparse(value if "://" in value else f"http://{value}")
    return (parsed.hostname or "").lower()


def domain_allowed(value: str, allowlist: list[str]) -> bool:
    """True when the host of ``value`` equals or is a subdomain of an allowlisted domain."""
    host = host_of(value)
    if not host:
        return False
    return any(host == d.lower() or host.endswith("." + d.lower()) for d in allowlist)


class ApprovalCondition(_Strict):
    """Optional condition that limits when approval is required."""

    arg: str
    domain_not_in: list[str] = Field(default_factory=list)
    greater_than: float | None = None


class ApprovalRule(_Strict):
    """A tool that requires human approval (optionally only when ``when`` holds)."""

    tool: str
    when: ApprovalCondition | None = None

    def applies(self, arguments: dict[str, Any]) -> bool:
        """Whether approval is required for these arguments."""
        if self.when is None:
            return True
        value = arguments.get(self.when.arg)
        if value is None:
            return True
        if self.when.domain_not_in and not domain_allowed(str(value), self.when.domain_not_in):
            return True
        if self.when.greater_than is not None:
            try:
                return float(value) > self.when.greater_than
            except (TypeError, ValueError):
                return True
        return False


class ArgConstraint(_Strict):
    """A constraint on a tool argument: a regex and/or a domain allowlist."""

    tool: str
    arg: str
    pattern: str | None = None
    domain_allowlist: list[str] = Field(default_factory=list)
    description: str = ""

    @field_validator("pattern")
    @classmethod
    def _regex(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"invalid regex {value!r}: {exc}") from exc
        return value

    def check(self, arguments: dict[str, Any]) -> str | None:
        """Return a violation message, or ``None`` if the constraint holds."""
        if self.arg not in arguments:
            return None
        value = str(arguments[self.arg])
        if self.pattern and not re.search(self.pattern, value):
            return f"{self.tool}.{self.arg}={value!r} does not match {self.pattern!r}"
        if self.domain_allowlist and not domain_allowed(value, self.domain_allowlist):
            return f"{self.tool}.{self.arg} destination {host_of(value)!r} is not allowlisted"
        return None


PiiType = Literal["email", "phone", "credit_card", "aadhaar", "pan", "ssn", "iban"]


def _default_pii() -> list[PiiType]:
    return ["credit_card", "ssn", "aadhaar", "pan", "iban", "phone"]


class ProtectedData(_Strict):
    """Data classes that must never appear in agent output or tool arguments."""

    canaries: bool = True
    system_prompt: bool = True
    pii_types: list[PiiType] = Field(default_factory=_default_pii)
    secret_patterns: list[str] = Field(default_factory=list)


class PolicyLimits(_Strict):
    """Resource limits evaluated by the ``resource`` detector."""

    max_tool_calls: int = Field(default=15, ge=1)
    max_turns: int = Field(default=12, ge=1)
    max_output_chars: int = Field(default=20_000, ge=100)
    max_tokens: int = Field(default=30_000, ge=100)
    max_wall_time_s: float = Field(default=60.0, gt=0)
    max_identical_tool_calls: int = Field(default=5, ge=1)


class PolicyDecision(BaseModel):
    """Result of evaluating one tool call against the policy."""

    allowed: bool
    approval_required: bool = False
    violations: list[str] = Field(default_factory=list)


class Policy(_Strict):
    """A complete security policy (see ``examples/policy.yaml``)."""

    version: Literal[1] = 1
    mode: Literal["observe", "block"] = "observe"
    allowed_tools: list[str] = Field(default_factory=list)
    forbidden_tools: list[str] = Field(default_factory=list)
    approval_required_tools: list[ApprovalRule] = Field(default_factory=list)
    arg_constraints: list[ArgConstraint] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    internal_email_domains: list[str] = Field(default_factory=list)
    protected_data: ProtectedData = Field(default_factory=ProtectedData)
    must_refuse: list[str] = Field(default_factory=list)
    must_not_refuse: list[str] = Field(default_factory=list)
    limits: PolicyLimits = Field(default_factory=PolicyLimits)
    approver_default: Literal["deny", "approve"] = "deny"

    def approval_required(self, name: str, arguments: dict[str, Any]) -> bool:
        """Whether calling ``name`` with ``arguments`` needs human approval."""
        return any(rule.tool == name and rule.applies(arguments) for rule in self.approval_required_tools)

    def evaluate_tool_call(
        self, name: str, arguments: dict[str, Any], *, approved: bool | None = None
    ) -> PolicyDecision:
        """Evaluate a tool call.

        Args:
            name: tool name.
            arguments: tool arguments.
            approved: approval state obtained by the agent before the call (``None`` = never
                requested).

        Returns:
            A :class:`PolicyDecision` listing every violated rule.
        """
        violations: list[str] = []
        if name in self.forbidden_tools:
            violations.append(f"forbidden tool '{name}'")
        elif self.allowed_tools and name not in self.allowed_tools:
            violations.append(f"tool '{name}' is not in allowed_tools")
        for constraint in self.arg_constraints:
            if constraint.tool == name:
                problem = constraint.check(arguments)
                if problem:
                    violations.append(problem)
        needs_approval = self.approval_required(name, arguments)
        if needs_approval and approved is not True:
            if approved is None:
                violations.append(f"'{name}' requires human approval but none was requested")
            else:
                violations.append(f"'{name}' was executed after approval was denied")
        return PolicyDecision(allowed=not violations, approval_required=needs_approval, violations=violations)


def load_policy(source: str | Path | dict[str, Any] | None, *, base_dir: Path | None = None) -> Policy:
    """Load a policy from a YAML path, an inline mapping, or return the default policy.

    Raises:
        ConfigError: if the file is missing or invalid (message names the field).
    """
    if source is None:
        return Policy()
    if isinstance(source, dict):
        data: Any = source
        origin = "policy"
    else:
        path = Path(source)
        if not path.is_absolute() and not path.exists() and base_dir is not None:
            path = base_dir / path
        if not path.exists():
            raise ConfigError(f"policy: file not found: {source} (hint: check the 'policy:' path)")
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ConfigError(f"policy: invalid YAML in {path}: {exc}") from exc
        origin = str(path)
    try:
        return Policy.model_validate(data or {})
    except ValidationError as exc:
        from agentguard.config.loader import format_validation_error

        raise ConfigError(format_validation_error(exc, prefix="policy", origin=origin)) from exc
