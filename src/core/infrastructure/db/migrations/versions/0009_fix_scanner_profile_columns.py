"""fix scanner profile columns

Revision ID: 0009_fix_scanner_profile_columns
Revises: 0008_create_m3_4_asset_scanner_management
Create Date: 2026-08-03 15:45:00.000000

Renomeia colunas da tabela scanner_profiles para paridade com o ORM:
- rate_limit_packets_per_sec -> rate_limit_per_second
- max_concurrency -> max_parallelism
- adiciona timeout_seconds (se não existir)
- custom_ports -> custom_ports_json (se não existir)
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009_fix_scanner_profile_cols"
down_revision: str | None = "0008_m3_4_asset_scanner_mgmt"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def _json_type(dialect_name: str) -> sa.types.TypeEngine[Any]:
    if dialect_name == "postgresql":
        return postgresql.JSONB()
    return sa.JSON()


def upgrade() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name
    json_t = _json_type(dialect_name)
    inspector = sa.inspect(bind)

    columns = [c["name"] for c in inspector.get_columns("scanner_profiles")]

    # 1. Renomear rate_limit_packets_per_sec -> rate_limit_per_second se existir coluna antiga
    if "rate_limit_packets_per_sec" in columns and "rate_limit_per_second" not in columns:
        op.alter_column("scanner_profiles", "rate_limit_packets_per_sec", new_column_name="rate_limit_per_second")
    elif "rate_limit_per_second" not in columns:
        op.add_column("scanner_profiles", sa.Column("rate_limit_per_second", sa.Integer(), nullable=False, server_default="50"))

    # 2. Renomear max_concurrency -> max_parallelism se existir coluna antiga
    if "max_concurrency" in columns and "max_parallelism" not in columns:
        op.alter_column("scanner_profiles", "max_concurrency", new_column_name="max_parallelism")
    elif "max_parallelism" not in columns:
        op.add_column("scanner_profiles", sa.Column("max_parallelism", sa.Integer(), nullable=False, server_default="10"))

    # 3. Adicionar timeout_seconds se não existir
    if "timeout_seconds" not in columns:
        op.add_column("scanner_profiles", sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="30"))

    # 4. Renomear custom_ports -> custom_ports_json e alterar tipo para JSONB/JSON
    if "custom_ports" in columns and "custom_ports_json" not in columns:
        op.alter_column("scanner_profiles", "custom_ports", new_column_name="custom_ports_json")
        if dialect_name == "postgresql":
            op.execute("ALTER TABLE scanner_profiles ALTER COLUMN custom_ports_json TYPE JSONB USING CASE WHEN custom_ports_json IS NULL OR custom_ports_json = '' THEN '[]'::jsonb ELSE custom_ports_json::jsonb END")
    elif "custom_ports_json" not in columns:
        op.add_column("scanner_profiles", sa.Column("custom_ports_json", json_t, nullable=False, server_default=sa.text("'[]'")))

    # 5. Ajustar coluna active -> enabled em monitoring_integrations se existir
    m_columns = [c["name"] for c in inspector.get_columns("monitoring_integrations")]
    if "active" in m_columns and "enabled" not in m_columns:
        op.alter_column("monitoring_integrations", "active", new_column_name="enabled")

    if "verify_tls" not in m_columns:
        op.add_column("monitoring_integrations", sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.text("true")))

    op.alter_column("monitoring_integrations", "created_by", nullable=True)

    # 6. Ajustar colunas em monitoring_sync_executions
    if inspector.has_table("monitoring_sync_executions"):
        sync_columns = [c["name"] for c in inspector.get_columns("monitoring_sync_executions")]
        if "assets_processed" not in sync_columns:
            op.add_column("monitoring_sync_executions", sa.Column("assets_processed", sa.Integer(), nullable=False, server_default="0"))
        if "assets_created" not in sync_columns:
            op.add_column("monitoring_sync_executions", sa.Column("assets_created", sa.Integer(), nullable=False, server_default="0"))
        if "assets_updated" not in sync_columns:
            op.add_column("monitoring_sync_executions", sa.Column("assets_updated", sa.Integer(), nullable=False, server_default="0"))
        if "errors_count" not in sync_columns:
            op.add_column("monitoring_sync_executions", sa.Column("errors_count", sa.Integer(), nullable=False, server_default="0"))
        if "error_summary" not in sync_columns:
            op.add_column("monitoring_sync_executions", sa.Column("error_summary", sa.Text(), nullable=True))
        if "created_at" not in sync_columns:
            op.add_column("monitoring_sync_executions", sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")))

    # 7. Ajustar coluna active -> enabled em scan_schedules se existir
    if inspector.has_table("scan_schedules"):
        sched_columns = [c["name"] for c in inspector.get_columns("scan_schedules")]
        if "active" in sched_columns and "enabled" not in sched_columns:
            op.alter_column("scan_schedules", "active", new_column_name="enabled")
        elif "enabled" not in sched_columns:
            op.add_column("scan_schedules", sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")))


def downgrade() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name
    inspector = sa.inspect(bind)

    columns = [c["name"] for c in inspector.get_columns("scanner_profiles")]

    if "rate_limit_per_second" in columns and "rate_limit_packets_per_sec" not in columns:
        op.alter_column("scanner_profiles", "rate_limit_per_second", new_column_name="rate_limit_packets_per_sec")

    if "max_parallelism" in columns and "max_concurrency" not in columns:
        op.alter_column("scanner_profiles", "max_parallelism", new_column_name="max_concurrency")

    if "timeout_seconds" in columns:
        op.drop_column("scanner_profiles", "timeout_seconds")

    if "custom_ports_json" in columns and "custom_ports" not in columns:
        if dialect_name == "postgresql":
            op.execute("ALTER TABLE scanner_profiles ALTER COLUMN custom_ports_json TYPE TEXT USING custom_ports_json::text")
        op.alter_column("scanner_profiles", "custom_ports_json", new_column_name="custom_ports")

    m_columns = [c["name"] for c in inspector.get_columns("monitoring_integrations")]
    if "enabled" in m_columns and "active" not in m_columns:
        op.alter_column("monitoring_integrations", "enabled", new_column_name="active")
