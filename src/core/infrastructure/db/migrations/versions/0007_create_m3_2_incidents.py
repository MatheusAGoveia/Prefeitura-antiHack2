"""create m3_2 incidents correlation tables

Revision ID: 0007_create_m3_2_incidents
Revises: 0006_harden_m3_1_integrity_and_outbox
Create Date: 2026-07-30 15:00:00.000000

Tabelas criadas:
- incidents: incidentes com índice único PARCIAL para status ativos, permitindo reabertura.
- incident_evidences: vínculos evento↔incidente com FK compostas tenant-aware.
- incident_status_history: histórico auditável imutável de transições.

Constraint UQ adicionada em security_events(tenant_id, event_id) para FK composta tenant-aware.
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op
from alembic.operations import Operations
from sqlalchemy.dialects import postgresql

revision: str = "0007_create_m3_2_incidents"
down_revision: str | None = "0006_harden_m3_1_integrity_and_outbox"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def _uuid_type(dialect_name: str) -> sa.types.TypeEngine[Any]:
    """Retorna o tipo UUID portável entre PostgreSQL e SQLite."""
    if dialect_name == "postgresql":
        return postgresql.UUID(as_uuid=True)
    return sa.String(length=36)


def _json_type(dialect_name: str) -> sa.types.TypeEngine[Any]:
    """Retorna o tipo JSON portável entre PostgreSQL e SQLite."""
    if dialect_name == "postgresql":
        return postgresql.JSONB()
    return sa.JSON()


def upgrade(op_ctx: Operations | None = None) -> None:
    op_impl = op_ctx if op_ctx is not None else op
    bind = op_ctx.get_bind() if op_ctx is not None else op.get_bind()
    dialect_name = bind.dialect.name
    inspector = sa.inspect(bind)

    uuid_t = _uuid_type(dialect_name)
    json_t = _json_type(dialect_name)

    # ------------------------------------------------------------------ #
    # 1. Adicionar UniqueConstraint (tenant_id, event_id) em security_events
    #    Necessário para referenciar FK composta tenant-aware de incident_evidences.
    # ------------------------------------------------------------------ #
    existing_uqs = inspector.get_unique_constraints("security_events")
    has_tenant_event_uq = any(
        uq["name"] == "uq_security_events_tenant_event" for uq in existing_uqs
    )
    if not has_tenant_event_uq:
        with op_impl.batch_alter_table("security_events") as batch_op:
            batch_op.create_unique_constraint(
                "uq_security_events_tenant_event", ["tenant_id", "event_id"]
            )

    # ------------------------------------------------------------------ #
    # 2. Criar tabela incidents
    # ------------------------------------------------------------------ #
    existing_tables = inspector.get_table_names()

    if "incidents" not in existing_tables:
        op_impl.create_table(
            "incidents",
            sa.Column("incident_id", uuid_t, primary_key=True, nullable=False),
            sa.Column("tenant_id", uuid_t, nullable=False),
            sa.Column("title", sa.String(length=256), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("severity", sa.String(length=32), nullable=False),
            sa.Column(
                "status",
                sa.String(length=32),
                nullable=False,
                server_default=sa.text("'open'"),
            ),
            sa.Column("correlation_key", sa.String(length=512), nullable=False),
            sa.Column("correlation_key_hash", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            # FK composta referenciável por tabelas filhas
            sa.UniqueConstraint("tenant_id", "incident_id", name="uq_incidents_tenant_incident"),
        )
        # Índices de performance
        op_impl.create_index("idx_incidents_tenant_id", "incidents", ["tenant_id"])
        op_impl.create_index(
            "idx_incidents_tenant_status", "incidents", ["tenant_id", "status"]
        )
        op_impl.create_index(
            "idx_incidents_tenant_created", "incidents", ["tenant_id", "created_at"]
        )
        # Índice único PARCIAL: somente incidentes em status ativo
        # Permite criar novo incidente após RESOLVED/CLOSED com a mesma chave de correlação.
        if dialect_name == "postgresql":
            op_impl.create_index(
                "idx_incidents_active_corrkey_unique",
                "incidents",
                ["tenant_id", "correlation_key_hash"],
                unique=True,
                postgresql_where=sa.text("status NOT IN ('resolved', 'closed')"),
            )
        else:
            op_impl.create_index(
                "idx_incidents_active_corrkey_unique",
                "incidents",
                ["tenant_id", "correlation_key_hash"],
                unique=True,
                sqlite_where=sa.text("status NOT IN ('resolved', 'closed')"),
            )

    # ------------------------------------------------------------------ #
    # 3. Criar tabela incident_evidences
    # ------------------------------------------------------------------ #
    if "incident_evidences" not in existing_tables:
        op_impl.create_table(
            "incident_evidences",
            sa.Column("evidence_id", uuid_t, primary_key=True, nullable=False),
            sa.Column("incident_id", uuid_t, nullable=False),
            sa.Column("tenant_id", uuid_t, nullable=False),
            sa.Column("event_id", uuid_t, nullable=False),
            sa.Column("evidence_hash", sa.String(length=64), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("raw_payload_masked", json_t, nullable=False),
            sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
            # FK composta tenant-aware: incident_evidences → incidents
            sa.ForeignKeyConstraint(
                ["tenant_id", "incident_id"],
                ["incidents.tenant_id", "incidents.incident_id"],
                name="fk_evidence_tenant_incident",
                ondelete="CASCADE",
            ),
            # FK composta tenant-aware: incident_evidences → security_events
            sa.ForeignKeyConstraint(
                ["tenant_id", "event_id"],
                ["security_events.tenant_id", "security_events.event_id"],
                name="fk_evidence_tenant_event",
            ),
            # Idempotência de vínculo: mesmo evento não duplica evidência
            sa.UniqueConstraint("incident_id", "event_id", name="uq_evidence_incident_event"),
        )
        op_impl.create_index("idx_incident_evidences_tenant", "incident_evidences", ["tenant_id"])
        op_impl.create_index(
            "idx_incident_evidences_incident", "incident_evidences", ["incident_id"]
        )

    # ------------------------------------------------------------------ #
    # 4. Criar tabela incident_status_history
    # ------------------------------------------------------------------ #
    if "incident_status_history" not in existing_tables:
        op_impl.create_table(
            "incident_status_history",
            sa.Column("history_id", uuid_t, primary_key=True, nullable=False),
            sa.Column("incident_id", uuid_t, nullable=False),
            sa.Column("tenant_id", uuid_t, nullable=False),
            sa.Column("from_status", sa.String(length=32), nullable=False),
            sa.Column("to_status", sa.String(length=32), nullable=False),
            sa.Column("actor_id", sa.String(length=128), nullable=False),
            sa.Column("reason", sa.Text(), nullable=False),
            sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
            # FK composta tenant-aware: status_history → incidents
            sa.ForeignKeyConstraint(
                ["tenant_id", "incident_id"],
                ["incidents.tenant_id", "incidents.incident_id"],
                name="fk_status_history_tenant_incident",
                ondelete="CASCADE",
            ),
        )
        op_impl.create_index(
            "idx_status_history_incident_ts",
            "incident_status_history",
            ["incident_id", "timestamp"],
        )
        op_impl.create_index(
            "idx_status_history_tenant", "incident_status_history", ["tenant_id"]
        )


def downgrade(op_ctx: Operations | None = None) -> None:
    op_impl = op_ctx if op_ctx is not None else op

    # Drops em ordem reversa de dependência
    op_impl.drop_index("idx_status_history_tenant", table_name="incident_status_history")
    op_impl.drop_index("idx_status_history_incident_ts", table_name="incident_status_history")
    op_impl.drop_table("incident_status_history")

    op_impl.drop_index("idx_incident_evidences_incident", table_name="incident_evidences")
    op_impl.drop_index("idx_incident_evidences_tenant", table_name="incident_evidences")
    op_impl.drop_table("incident_evidences")

    op_impl.drop_index("idx_incidents_active_corrkey_unique", table_name="incidents")
    op_impl.drop_index("idx_incidents_tenant_created", table_name="incidents")
    op_impl.drop_index("idx_incidents_tenant_status", table_name="incidents")
    op_impl.drop_index("idx_incidents_tenant_id", table_name="incidents")
    op_impl.drop_table("incidents")

    with op_impl.batch_alter_table("security_events") as batch_op:
        batch_op.drop_constraint("uq_security_events_tenant_event", type_="unique")
