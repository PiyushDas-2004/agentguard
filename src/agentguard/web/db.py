"""Database setup for the hosted web app: engine creation and schema migrations (Alembic)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Engine, create_engine, inspect
from sqlalchemy.pool import StaticPool

__all__ = [
    "MIGRATIONS_DIR",
    "alembic_config",
    "current_revision",
    "downgrade",
    "include_object",
    "make_engine",
    "upgrade",
]

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
WEB_PREFIX = "web_"


def include_object(obj: Any, name: str | None, type_: str, reflected: bool, compare_to: Any) -> bool:
    """Alembic filter: manage only the web app's tables (the CLI's tables share SQLModel.metadata)."""
    if type_ == "table":
        return bool(name and name.startswith(WEB_PREFIX))
    table = getattr(obj, "table", None)
    return table is None or str(table.name).startswith(WEB_PREFIX)


def make_engine(url: str) -> Engine:
    """Create the engine for ``url`` (SQLite file/in-memory or Postgres)."""
    if url.startswith("sqlite"):
        if url == "sqlite:///:memory:":
            return create_engine(url, connect_args={"check_same_thread": False}, poolclass=StaticPool)
        if url.startswith("sqlite:///"):
            Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
        return create_engine(url, connect_args={"check_same_thread": False})
    return create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=5, pool_recycle=1800)


def alembic_config() -> Config:
    """Alembic configuration pointing at the bundled migration scripts."""
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    return config


def upgrade(engine: Engine, revision: str = "head") -> None:
    """Bring the schema to ``revision`` (idempotent; runs at application start-up)."""
    config = alembic_config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, revision)


def downgrade(engine: Engine, revision: str) -> None:
    """Revert the schema to ``revision`` (operators/tests only)."""
    config = alembic_config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.downgrade(config, revision)


def current_revision(engine: Engine) -> str | None:
    """The schema revision recorded in the database, or ``None`` if unmigrated."""
    with engine.connect() as connection:
        if "alembic_version" not in inspect(connection).get_table_names():
            return None
        return MigrationContext.configure(connection).get_current_revision()
