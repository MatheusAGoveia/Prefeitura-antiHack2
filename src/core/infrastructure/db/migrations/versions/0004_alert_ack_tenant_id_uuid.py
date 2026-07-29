"""alter alert_acknowledgements.tenant_id to UUID

Revision ID: 0004_alert_ack_tenant_id_uuid
Revises: 0003_create_alert_acknowledgements
Create Date: 2026-07-29 14:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_alert_ack_tenant_id_uuid"
down_revision: str | None = "0003_create_alert_acknowledgements"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "alert_acknowledgements",
        "tenant_id",
        type_=postgresql.UUID(as_uuid=True),
        postgresql_using="tenant_id::uuid",
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "alert_acknowledgements",
        "tenant_id",
        type_=sa.String(length=64),
        existing_nullable=False,
    )
