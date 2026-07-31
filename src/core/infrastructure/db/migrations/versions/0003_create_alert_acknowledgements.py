"""create alert_acknowledgements table

Revision ID: 0003_create_alert_acknowledgements
Revises: 0002_create_audit_logs
Create Date: 2026-07-29 12:30:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_create_alert_ack"
down_revision: str | None = "0002_create_audit_logs"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "alert_acknowledgements",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("alert_id", sa.String(length=128), nullable=False),
        sa.Column("fingerprint", sa.String(length=128), nullable=False),
        sa.Column("reason", sa.String(length=512), nullable=False),
        sa.Column("acknowledged_by", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_alert_acknowledgements_alert_id"), "alert_acknowledgements", ["alert_id"], unique=False
    )
    op.create_index(
        op.f("ix_alert_acknowledgements_fingerprint"),
        "alert_acknowledgements",
        ["fingerprint"],
        unique=False,
    )
    op.create_index(
        op.f("ix_alert_acknowledgements_tenant_id"), "alert_acknowledgements", ["tenant_id"], unique=False
    )
    op.create_index(
        op.f("ix_alert_acknowledgements_timestamp"), "alert_acknowledgements", ["timestamp"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_alert_acknowledgements_timestamp"), table_name="alert_acknowledgements")
    op.drop_index(op.f("ix_alert_acknowledgements_tenant_id"), table_name="alert_acknowledgements")
    op.drop_index(op.f("ix_alert_acknowledgements_fingerprint"), table_name="alert_acknowledgements")
    op.drop_index(op.f("ix_alert_acknowledgements_alert_id"), table_name="alert_acknowledgements")
    op.drop_table("alert_acknowledgements")
