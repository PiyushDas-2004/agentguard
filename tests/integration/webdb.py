"""Database selection for the web app tests.

By default each test gets a private in-memory SQLite database. Set
``AGENTGUARD_TEST_DATABASE_URL`` (e.g. ``postgresql+psycopg://user:pw@127.0.0.1/agentguard_test``)
to run the same tests against a real Postgres server; the schema is wiped before each use, so
point it at a throw-away database. CI does this with a Postgres service container.
"""

from __future__ import annotations

import os

from sqlalchemy import create_engine, text

POSTGRES_URL = os.environ.get("AGENTGUARD_TEST_DATABASE_URL", "")


def fresh_database_url() -> str:
    """URL of an empty database for one app instance."""
    if not POSTGRES_URL:
        return "sqlite:///:memory:"
    engine = create_engine(POSTGRES_URL)
    try:
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
    finally:
        engine.dispose()
    return POSTGRES_URL
