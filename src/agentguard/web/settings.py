"""Web application settings, loaded from environment variables.

Production refuses to start with insecure settings (missing/weak secret key, private-network
scanning or plain-HTTP targets enabled, open sign-up without an explicit opt-in).
"""

from __future__ import annotations

import os
from typing import Literal

from pydantic import BaseModel, Field, SecretStr, ValidationError, model_validator

from agentguard.core.errors import ConfigError

__all__ = ["WebSettings", "load_settings"]


class WebSettings(BaseModel):
    """Runtime configuration of the hosted service."""

    env: Literal["development", "test", "production"] = "development"
    secret_key: SecretStr = Field(default=SecretStr(""), repr=False)
    database_url: str = "sqlite:///.agentguard/web.db"
    base_url: str = "http://localhost:8000"
    signup_code: SecretStr | None = Field(default=None, repr=False)
    open_signup: bool = False
    allow_private_targets: bool = False
    allow_http_targets: bool = False
    session_hours: int = Field(default=12, ge=1, le=24 * 30)
    max_concurrent_scans: int = Field(default=2, ge=1, le=16)
    max_queued_scans: int = Field(default=20, ge=1, le=1000)
    scans_per_user_per_day: int = Field(default=20, ge=1, le=10_000)
    max_trials: int = Field(default=3, ge=1, le=10)
    max_cases_per_scan: int = Field(default=400, ge=1, le=5000)
    target_requests_per_second: float = Field(default=2.0, gt=0, le=50)
    request_timeout_seconds: float = Field(default=30.0, gt=0, le=120)
    retention_days: int = Field(default=30, ge=1, le=3650)
    max_scan_minutes: int = Field(default=30, ge=1, le=24 * 60)
    trusted_proxy_hops: int = Field(default=1, ge=0, le=5)

    @property
    def production(self) -> bool:
        """True in production."""
        return self.env == "production"

    @property
    def secure_cookies(self) -> bool:
        """Cookies get the ``Secure`` flag unless running plain-HTTP development/tests."""
        return self.production or self.base_url.startswith("https://")

    @model_validator(mode="after")
    def _production_guards(self) -> WebSettings:
        if self.env != "production":
            return self
        problems = []
        if len(self.secret_key.get_secret_value()) < 32:
            problems.append("AGENTGUARD_SECRET_KEY must be set to at least 32 random characters")
        if self.allow_private_targets:
            problems.append("AGENTGUARD_ALLOW_PRIVATE_TARGETS must be false in production")
        if self.allow_http_targets:
            problems.append("AGENTGUARD_ALLOW_HTTP_TARGETS must be false in production")
        if not self.base_url.startswith("https://"):
            problems.append("AGENTGUARD_BASE_URL must be an https:// URL in production")
        if not self.open_signup and not (self.signup_code and len(self.signup_code.get_secret_value()) >= 12):
            problems.append("set AGENTGUARD_SIGNUP_CODE (>= 12 chars) or explicitly AGENTGUARD_OPEN_SIGNUP=true")
        if problems:
            raise ValueError("; ".join(problems))
        return self


_ENV = {
    "env": "AGENTGUARD_ENV",
    "secret_key": "AGENTGUARD_SECRET_KEY",  # pragma: allowlist secret - env var name, not a value
    "database_url": "DATABASE_URL",
    "base_url": "AGENTGUARD_BASE_URL",
    "signup_code": "AGENTGUARD_SIGNUP_CODE",
    "open_signup": "AGENTGUARD_OPEN_SIGNUP",
    "allow_private_targets": "AGENTGUARD_ALLOW_PRIVATE_TARGETS",
    "allow_http_targets": "AGENTGUARD_ALLOW_HTTP_TARGETS",
    "session_hours": "AGENTGUARD_SESSION_HOURS",
    "max_concurrent_scans": "AGENTGUARD_MAX_CONCURRENT_SCANS",
    "max_queued_scans": "AGENTGUARD_MAX_QUEUED_SCANS",
    "scans_per_user_per_day": "AGENTGUARD_SCANS_PER_USER_PER_DAY",
    "max_trials": "AGENTGUARD_MAX_TRIALS",
    "target_requests_per_second": "AGENTGUARD_TARGET_RPS",
    "retention_days": "AGENTGUARD_RETENTION_DAYS",
    "max_scan_minutes": "AGENTGUARD_MAX_SCAN_MINUTES",
    "trusted_proxy_hops": "AGENTGUARD_TRUSTED_PROXY_HOPS",
}


def load_settings(environ: dict[str, str] | None = None) -> WebSettings:
    """Build :class:`WebSettings` from environment variables.

    Raises:
        ConfigError: invalid or insecure configuration (message names the variables).
    """
    source = os.environ if environ is None else environ
    data: dict[str, object] = {}
    for field, var in _ENV.items():
        value = source.get(var)
        if value is None or value == "":
            continue
        data[field] = (
            value.strip().lower() in {"1", "true", "yes"}
            if field in {"open_signup", "allow_private_targets", "allow_http_targets"}
            else value
        )
    if "base_url" not in data and source.get("RENDER_EXTERNAL_URL"):
        data["base_url"] = source["RENDER_EXTERNAL_URL"]  # set automatically by Render
    if "database_url" in data:
        url = str(data["database_url"])
        if url.startswith("postgres://"):
            url = "postgresql+psycopg://" + url.removeprefix("postgres://")
        elif url.startswith("postgresql://"):
            url = "postgresql+psycopg://" + url.removeprefix("postgresql://")
        data["database_url"] = url
    try:
        return WebSettings.model_validate(data)
    except ValidationError as exc:
        reasons = "; ".join(str(e["msg"]).removeprefix("Value error, ") for e in exc.errors())
        raise ConfigError(f"insecure or invalid web settings: {reasons}") from None
