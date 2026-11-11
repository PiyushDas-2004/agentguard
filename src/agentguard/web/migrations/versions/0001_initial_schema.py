"""Initial schema of the hosted web app (users, sessions, targets, scans, audit events).

Revision ID: 0001
Revises:
Create Date: 2026-11-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "web_audit",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("event", sa.String(length=60), nullable=False),
        sa.Column("ip", sa.String(length=64), nullable=False),
        sa.Column("detail", sa.String(length=500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("web_audit", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_web_audit_created_at"), ["created_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_web_audit_user_id"), ["user_id"], unique=False)

    op.create_table(
        "web_users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("failed_logins", sa.Integer(), nullable=False),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("web_users", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_web_users_email"), ["email"], unique=True)

    op.create_table(
        "web_sessions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("csrf_token", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["web_users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("web_sessions", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_web_sessions_expires_at"), ["expires_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_web_sessions_user_id"), ["user_id"], unique=False)

    op.create_table(
        "web_targets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("origin", sa.String(length=300), nullable=False),
        sa.Column("request_template", sa.Text(), nullable=True),
        sa.Column("text_path", sa.String(length=200), nullable=False),
        sa.Column("tool_calls_path", sa.String(length=200), nullable=False),
        sa.Column("model", sa.String(length=120), nullable=False),
        sa.Column("verification_token", sa.String(length=100), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("canary", sa.String(length=40), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["web_users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "url", name="uq_target_user_url"),
    )
    with op.batch_alter_table("web_targets", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_web_targets_user_id"), ["user_id"], unique=False)

    op.create_table(
        "web_scans",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("categories", sa.String(length=500), nullable=False),
        sa.Column("trials", sa.Integer(), nullable=False),
        sa.Column("mutations", sa.Boolean(), nullable=False),
        sa.Column("judge", sa.String(length=20), nullable=False),
        sa.Column("judge_model", sa.String(length=120), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("progress_done", sa.Integer(), nullable=False),
        sa.Column("progress_total", sa.Integer(), nullable=False),
        sa.Column("error", sa.String(length=1000), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("grade", sa.String(length=2), nullable=True),
        sa.Column("result_json", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["web_targets.id"],
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["web_users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("web_scans", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_web_scans_created_at"), ["created_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_web_scans_target_id"), ["target_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_web_scans_user_id"), ["user_id"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("web_scans", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_web_scans_user_id"))
        batch_op.drop_index(batch_op.f("ix_web_scans_target_id"))
        batch_op.drop_index(batch_op.f("ix_web_scans_created_at"))

    op.drop_table("web_scans")
    with op.batch_alter_table("web_targets", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_web_targets_user_id"))

    op.drop_table("web_targets")
    with op.batch_alter_table("web_sessions", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_web_sessions_user_id"))
        batch_op.drop_index(batch_op.f("ix_web_sessions_expires_at"))

    op.drop_table("web_sessions")
    with op.batch_alter_table("web_users", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_web_users_email"))

    op.drop_table("web_users")
    with op.batch_alter_table("web_audit", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_web_audit_user_id"))
        batch_op.drop_index(batch_op.f("ix_web_audit_created_at"))

    op.drop_table("web_audit")
