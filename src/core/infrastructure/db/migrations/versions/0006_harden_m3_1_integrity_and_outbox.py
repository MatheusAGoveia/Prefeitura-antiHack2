"""harden m3_1 integrity and create outbox_events table

Revision ID: 0006_harden_m3_1_integrity_and_outbox
Revises: 0005_create_m3_assets_security_events
Create Date: 2026-07-30 11:00:00.000000

"""

import contextlib
from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op
from alembic.operations import Operations
from sqlalchemy.dialects import postgresql

revision: str = "0006_harden_m3_1_integrity_and_outbox"
down_revision: str | None = "0005_create_m3_assets_security_events"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade(op_ctx: Operations | None = None) -> None:
    op_impl = op_ctx if op_ctx is not None else op
    bind = op_ctx.get_bind() if op_ctx is not None else op.get_bind()
    dialect_name = bind.dialect.name

    uuid_type: sa.types.TypeEngine[Any] = (
        postgresql.UUID(as_uuid=True) if dialect_name == "postgresql" else sa.String(length=36)
    )
    json_type: sa.types.TypeEngine[Any] = (
        postgresql.JSONB() if dialect_name == "postgresql" else sa.JSON()
    )

    # 1. Ajustar índice único de ativos para considerar apenas ativos ativos (is_active = true)
    with op_impl.batch_alter_table("assets") as batch_op, contextlib.suppress(Exception):
        batch_op.drop_constraint("uq_assets_tenant_service_env", type_="unique")


    if dialect_name == "postgresql":
        op_impl.create_index(
            "idx_assets_active_service_env_unique",
            "assets",
            ["tenant_id", "service_name", "environment"],
            unique=True,
            postgresql_where=sa.text("is_active = true"),
        )
    else:
        op_impl.create_index(
            "idx_assets_active_service_env_unique",
            "assets",
            ["tenant_id", "service_name", "environment"],
            unique=True,
            sqlite_where=sa.text("is_active = 1"),
        )

    # 2. Criar tabela outbox_events
    op_impl.create_table(
        "outbox_events",
        sa.Column("outbox_event_id", uuid_type, primary_key=True, nullable=False),
        sa.Column("tenant_id", uuid_type, nullable=False),
        sa.Column("aggregate_type", sa.String(length=64), nullable=False),
        sa.Column("aggregate_id", uuid_type, nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("payload", json_type, nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column(
            "status", sa.String(length=32), nullable=False, server_default=sa.text("'pending'")
        ),
        sa.Column(
            "retry_count", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=1024), nullable=True),
        sa.UniqueConstraint(
            "tenant_id", "idempotency_key", name="uq_outbox_events_idempotency"
        ),
    )
    op_impl.create_index("idx_outbox_tenant", "outbox_events", ["tenant_id"])
    op_impl.create_index(
        "idx_outbox_status_next_retry", "outbox_events", ["status", "next_retry_at"]
    )


def downgrade(op_ctx: Operations | None = None) -> None:
    op_impl = op_ctx if op_ctx is not None else op

    op_impl.drop_table("outbox_events")
    op_impl.drop_index("idx_assets_active_service_env_unique", table_name="assets")
    with op_impl.batch_alter_table("assets") as batch_op:
        batch_op.create_unique_constraint(
            "uq_assets_tenant_service_env", ["tenant_id", "service_name", "environment"]
        )
