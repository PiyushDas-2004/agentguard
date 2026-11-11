"""Database tables of the hosted service (SQLite locally, Postgres in production).

No secrets are stored: passwords are argon2id hashes, session tokens are stored as SHA-256
digests, and LLM API keys / agent auth headers are never persisted.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Column, DateTime, Dialect, Text, TypeDecorator, UniqueConstraint
from sqlmodel import Field, SQLModel

from agentguard.core.types import utcnow

__all__ = ["AuditEvent", "Scan", "Target", "UTCDateTime", "User", "UserSession"]


class UTCDateTime(TypeDecorator[datetime]):
    """Timestamp stored as UTC (``timestamptz`` on Postgres) and always read back timezone-aware.

    SQLite has no time zone type and would silently drop offsets, so values are normalized to
    UTC on write; naive values (legacy rows, SQLite) are interpreted as UTC on read.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return (value if value.tzinfo else value.replace(tzinfo=UTC)).astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _when(*, required: bool = False, index: bool = False, now: bool = False) -> Any:
    """Timezone-aware timestamp column (``timestamptz`` on Postgres; all values are UTC)."""
    column: Column[datetime] = Column(UTCDateTime(), nullable=not required, index=index)
    if now:
        return Field(default_factory=utcnow, sa_column=column)
    return Field(default=None, sa_column=column) if not required else Field(sa_column=column)


class User(SQLModel, table=True):
    """A registered user."""

    __tablename__ = "web_users"

    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True, max_length=254)
    password_hash: str = Field(max_length=255)
    created_at: datetime = _when(required=True, now=True)
    failed_logins: int = 0
    disabled_at: datetime | None = _when()  # set by an administrator; disabled users cannot sign in


class UserSession(SQLModel, table=True):
    """A server-side session; ``id`` is the SHA-256 of the cookie token (the token is not stored)."""

    __tablename__ = "web_sessions"

    id: str = Field(primary_key=True, max_length=64)
    user_id: int = Field(index=True, foreign_key="web_users.id")
    csrf_token: str = Field(max_length=64)
    created_at: datetime = _when(required=True, now=True)
    expires_at: datetime = _when(required=True, index=True)


class Target(SQLModel, table=True):
    """An agent endpoint owned by a user; scannable only once its origin is verified."""

    __tablename__ = "web_targets"
    __table_args__ = (UniqueConstraint("user_id", "url", name="uq_target_user_url"),)

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(index=True, foreign_key="web_users.id")
    name: str = Field(max_length=80)
    kind: str = Field(max_length=20)  # http | openai_compat
    url: str = Field(max_length=2048)
    origin: str = Field(max_length=300)
    request_template: str = Field(default="", sa_column=Column(Text))
    text_path: str = Field(default="$.reply", max_length=200)
    tool_calls_path: str = Field(default="", max_length=200)
    model: str = Field(default="", max_length=120)
    verification_token: str = Field(max_length=100)
    verified_at: datetime | None = _when()
    canary: str = Field(max_length=40)
    created_at: datetime = _when(required=True, now=True)


class Scan(SQLModel, table=True):
    """A scan job and, when finished, its full ``RunResult`` JSON."""

    __tablename__ = "web_scans"

    id: str = Field(primary_key=True, max_length=32)
    user_id: int = Field(index=True, foreign_key="web_users.id")
    target_id: int = Field(index=True, foreign_key="web_targets.id")
    status: str = Field(default="queued", max_length=20)  # queued|running|completed|failed|cancelled
    categories: str = Field(default="", max_length=500)
    trials: int = 1
    mutations: bool = False
    judge: str = Field(default="deterministic", max_length=20)  # deterministic|gemini
    judge_model: str = Field(default="", max_length=120)
    created_at: datetime = _when(required=True, index=True, now=True)
    started_at: datetime | None = _when()
    finished_at: datetime | None = _when()
    progress_done: int = 0
    progress_total: int = 0
    error: str = Field(default="", max_length=1000)
    risk_score: float | None = None
    grade: str | None = Field(default=None, max_length=2)
    result_json: str | None = Field(default=None, sa_column=Column(Text))


class AuditEvent(SQLModel, table=True):
    """Security-relevant event (sign-in, failures, scans, verification, deletions)."""

    __tablename__ = "web_audit"

    id: int | None = Field(default=None, primary_key=True)
    user_id: int | None = Field(default=None, index=True)
    event: str = Field(max_length=60)
    ip: str = Field(default="", max_length=64)
    detail: str = Field(default="", max_length=500)
    created_at: datetime = _when(required=True, index=True, now=True)
