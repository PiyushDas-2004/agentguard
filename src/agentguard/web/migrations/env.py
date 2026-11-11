"""Alembic environment for the hosted web app (online mode only, driven by ``agentguard.web.db``)."""

from __future__ import annotations

from alembic import context
from sqlmodel import SQLModel

import agentguard.web.models  # noqa: F401  (registers the web tables on SQLModel.metadata)
from agentguard.web.db import include_object


def run_migrations() -> None:
    """Run the migrations on the connection handed over by ``agentguard.web.db``."""
    connection = context.config.attributes.get("connection")
    if connection is None:
        raise RuntimeError("run migrations through agentguard.web.db.upgrade(engine)")
    context.configure(
        connection=connection,
        target_metadata=SQLModel.metadata,
        include_object=include_object,
        render_as_batch=True,  # SQLite needs batch mode for ALTER TABLE
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# Alembic executes this file with its context proxy installed; a plain import (docs, smoke tests)
# must not try to run migrations.
if hasattr(context, "config"):
    run_migrations()
