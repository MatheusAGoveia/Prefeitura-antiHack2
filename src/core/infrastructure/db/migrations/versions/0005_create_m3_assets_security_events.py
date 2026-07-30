"""create assets, security_events and correlation_rule_versions tables

Revision ID: 0005_create_m3_assets_security_events
Revises: 0004_alert_ack_tenant_id_uuid
Create Date: 2026-07-30 10:00:00.000000

"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op
from alembic.operations import Operations
from sqlalchemy.dialects import postgresql

revision: str = "0005_create_m3_assets_security_events"
down_revision: str | None = "0004_alert_ack_tenant_id_uuid"
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

    # 1. Tabela assets
    op_impl.create_table(
        "assets",
        sa.Column("asset_id", uuid_type, primary_key=True, nullable=False),
        sa.Column("tenant_id", uuid_type, nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("asset_type", sa.String(length=64), nullable=False),
        sa.Column("service_name", sa.String(length=128), nullable=False),
        sa.Column("environment", sa.String(length=64), nullable=False),
        sa.Column("criticality", sa.String(length=32), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("hostname_or_ip", sa.String(length=256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "tenant_id", "service_name", "environment", name="uq_assets_tenant_service_env"
        ),
    )
    op_impl.create_index("idx_assets_tenant_id", "assets", ["tenant_id"])
    op_impl.create_index(
        "idx_assets_tenant_service_env", "assets", ["tenant_id", "service_name", "environment"]
    )

    # 2. Tabela security_events
    op_impl.create_table(
        "security_events",
        sa.Column("event_id", uuid_type, primary_key=True, nullable=False),
        sa.Column("tenant_id", uuid_type, nullable=False),
        sa.Column(
            "asset_id",
            uuid_type,
            sa.ForeignKey("assets.asset_id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", json_type, nullable=False),
        sa.Column("evidence_hash", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column(
            "is_asset_resolved", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "tenant_id", "source", "idempotency_key", name="uq_security_events_idempotency"
        ),
    )
    op_impl.create_index(
        "idx_security_events_tenant_occurred", "security_events", ["tenant_id", "occurred_at"]
    )
    op_impl.create_index(
        "idx_security_events_tenant_asset_occurred",
        "security_events",
        ["tenant_id", "asset_id", "occurred_at"],
    )

    # 3. Tabela correlation_rule_versions
    op_impl.create_table(
        "correlation_rule_versions",
        sa.Column("rule_version_id", uuid_type, primary_key=True, nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("rule_version", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("rule_id", "rule_version", name="uq_rule_id_version"),
    )


def downgrade(op_ctx: Operations | None = None) -> None:
    op_impl = op_ctx if op_ctx is not None else op
    op_impl.drop_table("correlation_rule_versions")
    op_impl.drop_table("security_events")
    op_impl.drop_table("assets")
