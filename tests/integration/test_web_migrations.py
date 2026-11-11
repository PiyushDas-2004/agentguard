"""Alembic migrations: they build exactly the schema the models describe, and can be reverted."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("alembic")
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect
from sqlmodel import SQLModel

from agentguard.web import models
from agentguard.web.db import current_revision, downgrade, include_object, make_engine, upgrade
from tests.integration.webdb import POSTGRES_URL, fresh_database_url

WEB_TABLES = {"web_users", "web_sessions", "web_targets", "web_scans", "web_audit"}


@pytest.fixture
def database_url(tmp_path: Path) -> str:
    return fresh_database_url() if POSTGRES_URL else f"sqlite:///{tmp_path / 'web.db'}"


def _schema_diff(url: str) -> list[object]:
    engine = make_engine(url)
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(
                connection, opts={"include_object": include_object, "compare_type": True}
            )
            return list(compare_metadata(context, SQLModel.metadata))
    finally:
        engine.dispose()


def test_migrations_match_the_models(database_url: str) -> None:
    engine = make_engine(database_url)
    upgrade(engine)
    assert current_revision(engine) == "0001"
    assert set(inspect(engine).get_table_names()) >= WEB_TABLES
    engine.dispose()
    assert _schema_diff(database_url) == [], "models changed without a migration: run alembic revision"


def test_upgrade_is_idempotent_and_downgrade_reverts(database_url: str) -> None:
    engine = make_engine(database_url)
    upgrade(engine)
    upgrade(engine)  # second start-up is a no-op
    downgrade(engine, "base")
    assert not WEB_TABLES & set(inspect(engine).get_table_names())
    upgrade(engine)
    assert current_revision(engine) == "0001"
    engine.dispose()


def test_timestamps_round_trip_as_utc(database_url: str) -> None:
    from datetime import UTC, datetime, timedelta, timezone

    from sqlmodel import Session

    engine = make_engine(database_url)
    upgrade(engine)
    local = datetime(2026, 1, 2, 15, 30, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    with Session(engine) as session:
        user = models.User(email="tz@example.com", password_hash="x", created_at=local)
        session.add(user)
        session.commit()
        session.refresh(user)
        stored = user.created_at if user.created_at.tzinfo else user.created_at.replace(tzinfo=UTC)
    assert stored == local  # same instant, regardless of the server's time zone
    engine.dispose()
