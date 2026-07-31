"""
Modelos ORM SQLAlchemy do Core
GovSec Shield — Infrastructure DB Models
"""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from src.core.domain.entities import TenantStatus


class Base(DeclarativeBase):
    pass


class TenantModel(Base):
    """Modelo relacional para a tabela tenants."""

    __tablename__ = "tenants"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    status: Mapped[TenantStatus] = mapped_column(
        SQLEnum(TenantStatus, name="tenant_status_enum", native_enum=False),
        nullable=False,
        default=TenantStatus.ACTIVE,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class AuditLogModel(Base):
    """Modelo relacional para a tabela audit_logs (Persistência Operacional de Logs)."""

    __tablename__ = "audit_logs"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    raw_data: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )


class AlertAcknowledgementModel(Base):
    """Modelo relacional para a tabela alert_acknowledgements."""

    __tablename__ = "alert_acknowledgements"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    alert_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    acknowledged_by: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )


class AssetModel(Base):
    """Modelo relacional para a tabela assets."""

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("tenant_id", "asset_id", name="uq_assets_tenant_asset"),
        Index(
            "idx_assets_active_service_env_unique",
            "tenant_id",
            "service_name",
            "environment",
            unique=True,
            postgresql_where=text("is_active = true"),
            sqlite_where=text("is_active = 1"),
        ),
        Index("idx_assets_tenant_id", "tenant_id"),
        Index("idx_assets_tenant_service_env", "tenant_id", "service_name", "environment"),
    )

    asset_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(64), nullable=False)
    service_name: Mapped[str] = mapped_column(String(128), nullable=False)
    environment: Mapped[str] = mapped_column(String(64), nullable=False)
    criticality: Mapped[str] = mapped_column(String(32), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    hostname_or_ip: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class SecurityEventModel(Base):
    """Modelo relacional para a tabela security_events."""

    __tablename__ = "security_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "asset_id"],
            ["assets.tenant_id", "assets.asset_id"],
            name="fk_security_events_tenant_asset",
        ),
        UniqueConstraint(
            "tenant_id", "source", "idempotency_key", name="uq_security_events_idempotency"
        ),
        # Constraint composta necessária para FK tenant-aware de incident_evidences
        UniqueConstraint("tenant_id", "event_id", name="uq_security_events_tenant_event"),
        Index("idx_security_events_tenant_occurred", "tenant_id", "occurred_at"),
        Index(
            "idx_security_events_tenant_asset_occurred",
            "tenant_id",
            "asset_id",
            "occurred_at",
        ),
    )

    event_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    asset_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False
    )
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    is_asset_resolved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class CorrelationRuleVersionModel(Base):
    """Modelo relacional para a tabela correlation_rule_versions."""

    __tablename__ = "correlation_rule_versions"
    __table_args__ = (UniqueConstraint("rule_id", "rule_version", name="uq_rule_id_version"),)

    rule_version_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class OutboxEventModel(Base):
    """Modelo relacional para a tabela outbox_events (Transactional Outbox Pattern)."""

    __tablename__ = "outbox_events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_outbox_events_idempotency"),
        Index("idx_outbox_status_next_retry", "status", "next_retry_at"),
        Index("idx_outbox_status_claim_expires", "status", "claim_expires_at"),
        Index("idx_outbox_tenant", "tenant_id"),
    )

    outbox_event_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    aggregate_type: Mapped[str] = mapped_column(String(64), nullable=False)
    aggregate_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False
    )
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    retry_count: Mapped[int] = mapped_column(default=0, nullable=False)
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claim_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(String(1024), nullable=True)


class IncidentModel(Base):
    """
    Modelo relacional para a tabela incidents (M3.2).

    Garantias de integridade:
    - UNIQUE(tenant_id, incident_id): permite FK composta de tabelas filhas (tenant-aware).
    - Índice único PARCIAL (status NOT IN ('resolved','closed')): permite reabrir incidente
      após resolução/fechamento sem violar unicidade de chave de correlação.
    - status usa lowercase (convenção única: domínio StrEnum + banco + API).
    """

    __tablename__ = "incidents"
    __table_args__ = (
        # FK composta referenciável por tabelas filhas (tenant-aware)
        UniqueConstraint("tenant_id", "incident_id", name="uq_incidents_tenant_incident"),
        # CHECK constraint para validação estrita de status no banco de dados
        CheckConstraint(
            "status IN ('open', 'acknowledged', 'investigating', 'contained', 'resolved', 'closed')",
            name="chk_incidents_status_valid",
        ),
        # Índice único PARCIAL: apenas incidentes ativos (permite reabertura pós-RESOLVED/CLOSED)
        Index(
            "idx_incidents_active_corrkey_unique",
            "tenant_id",
            "correlation_key_hash",
            unique=True,
            postgresql_where=text("status NOT IN ('resolved', 'closed')"),
            sqlite_where=text("status NOT IN ('resolved', 'closed')"),
        ),
        Index("idx_incidents_tenant_status", "tenant_id", "status"),
        Index("idx_incidents_tenant_created", "tenant_id", "created_at"),
    )

    incident_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    correlation_key: Mapped[str] = mapped_column(String(512), nullable=False)
    correlation_key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class IncidentEvidenceModel(Base):
    """
    Modelo relacional para a tabela incident_evidences (M3.2).

    Garantias de integridade:
    - FK composta (tenant_id, incident_id) → incidents: previne cross-tenant.
    - FK composta (tenant_id, event_id) → security_events: previne cross-tenant de eventos.
    - UNIQUE(incident_id, event_id): idempotência de vínculo — mesmo evento não duplica evidência.
    - raw_payload_masked: somente payload previamente sanitizado (sem tokens, senhas ou headers).
    """

    __tablename__ = "incident_evidences"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "incident_id"],
            ["incidents.tenant_id", "incidents.incident_id"],
            name="fk_evidence_tenant_incident",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "event_id"],
            ["security_events.tenant_id", "security_events.event_id"],
            name="fk_evidence_tenant_event",
        ),
        UniqueConstraint("incident_id", "event_id", name="uq_evidence_incident_event"),
        Index("idx_incident_evidences_tenant", "tenant_id"),
        Index("idx_incident_evidences_incident", "incident_id"),
    )

    evidence_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    incident_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    event_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    raw_payload_masked: Mapped[dict[str, Any]] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class IncidentStatusHistoryModel(Base):
    """
    Modelo relacional para a tabela incident_status_history (M3.2).

    Registro auditável imutável de toda transição de estado de incidente.
    FK composta (tenant_id, incident_id) → incidents garante isolamento cross-tenant.
    """

    __tablename__ = "incident_status_history"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "incident_id"],
            ["incidents.tenant_id", "incidents.incident_id"],
            name="fk_status_history_tenant_incident",
            ondelete="CASCADE",
        ),
        Index("idx_status_history_incident_ts", "incident_id", "timestamp"),
        Index("idx_status_history_tenant", "tenant_id"),
    )

    history_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    incident_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    from_status: Mapped[str] = mapped_column(String(32), nullable=False)
    to_status: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
