"""alter alert_acknowledgements.tenant_id to UUID

Revision ID: 0004_alert_ack_tenant_id_uuid
Revises: 0003_create_alert_acknowledgements
Create Date: 2026-07-29 14:00:00.000000

"""
import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from alembic.operations import Operations
from sqlalchemy.dialects import postgresql

revision: str = "0004_alert_ack_tenant_id_uuid"
down_revision: str | None = "0003_create_alert_acknowledgements"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

# Mapeamento explícito, versionado e auditável entre slugs legados e UUIDs oficiais dos tenants reais.
# NOTA: Em produção ou staging, cadastre aqui os UUIDs oficiais dos tenants antes de executar a migração.
# Slugs não cadastrados neste dicionário farão a migração falhar fechada (Fail-Closed).
LEGACY_TENANT_MAP: dict[str, str] = {}


def upgrade(op_ctx: Operations | None = None) -> None:
    bind = op_ctx.get_bind() if op_ctx is not None else op.get_bind()
    op_impl = op_ctx if op_ctx is not None else op

    # 1. Aplicar mapeamento explícito e auditado de slugs legados para UUIDs oficiais
    for legacy_slug, canonical_uuid in LEGACY_TENANT_MAP.items():
        bind.execute(
            sa.text(
                "UPDATE alert_acknowledgements SET tenant_id = :canonical_uuid WHERE tenant_id = :legacy_slug"
            ),
            {"canonical_uuid": canonical_uuid, "legacy_slug": legacy_slug},
        )

    # 2. Identificar se existem registros com tenant_id que não são UUIDs válidos (Fail-Closed)
    result = bind.execute(sa.text("SELECT DISTINCT tenant_id FROM alert_acknowledgements WHERE tenant_id IS NOT NULL"))
    invalid_tenants: list[str] = []
    for row in result.fetchall():
        val = str(row[0])
        try:
            uuid.UUID(val)
        except (ValueError, TypeError):
            invalid_tenants.append(val)

    if invalid_tenants:
        raise ValueError(
            f"Migração 0004 interrompida (Fail-Closed): Foram encontrados registros em 'alert_acknowledgements' "
            f"com tenant_id não-UUID não mapeado: {invalid_tenants}. "
            f"Consulte o procedimento operacional de saneamento de dados legados "
            f"(docs/operational/legacy_tenant_cleanup.md) para realizar o mapeamento explícito do UUID oficial "
            f"antes de prosseguir."
        )

    # 3. Alterar a coluna tenant_id para postgresql.UUID
    dialect_name = bind.dialect.name
    if dialect_name == "postgresql":
        op_impl.alter_column(
            "alert_acknowledgements",
            "tenant_id",
            type_=postgresql.UUID(as_uuid=True),
            postgresql_using="tenant_id::uuid",
            existing_nullable=False,
        )
    else:
        with op_impl.batch_alter_table("alert_acknowledgements") as batch_op:
            batch_op.alter_column(
                "tenant_id",
                type_=sa.String(length=36),
                existing_nullable=False,
            )


def downgrade(op_ctx: Operations | None = None) -> None:
    bind = op_ctx.get_bind() if op_ctx is not None else op.get_bind()
    op_impl = op_ctx if op_ctx is not None else op

    dialect_name = bind.dialect.name
    if dialect_name == "postgresql":
        op_impl.alter_column(
            "alert_acknowledgements",
            "tenant_id",
            type_=sa.String(length=64),
            postgresql_using="tenant_id::text",
            existing_nullable=False,
        )
    else:
        with op_impl.batch_alter_table("alert_acknowledgements") as batch_op:
            batch_op.alter_column(
                "tenant_id",
                type_=sa.String(length=64),
                existing_nullable=False,
            )
