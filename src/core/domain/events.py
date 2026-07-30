"""
Eventos de Domínio Core
GovSec Shield — Domain Events
"""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class DomainEvent(BaseModel):
    """Envelope base para eventos de domínio conforme M0.6."""

    event_id: UUID = Field(default_factory=uuid4)
    event_type: str
    tenant_id: UUID | None = None
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    schema_version: str = "1.0.0"


class TenantCreatedEvent(DomainEvent):
    """Evento disparado quando um novo Tenant é criado."""

    event_type: str = "TenantCreatedEvent"
    name: str
    slug: str


class LogIngestedEvent(DomainEvent):
    """Evento disparado quando um log é ingerido na plataforma."""

    event_type: str = "LogIngestedEvent"
    source: str
    raw_data: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AlertAcknowledgedEvent(DomainEvent):
    """Evento disparado quando um alerta é reconhecido por um operador humano."""

    event_type: str = "AlertAcknowledgedEvent"
    alert_id: str
    fingerprint: str
    reason: str
    acknowledged_by: str
    acknowledged_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SecurityEventReceivedEvent(DomainEvent):
    """Evento disparado após a persistência transacional bem-sucedida de um novo SecurityEvent."""

    event_type: str = "SecurityEventReceivedEvent"
    security_event_id: UUID
    source: str
    security_event_type: str
    severity: str
    is_asset_resolved: bool
    asset_id: UUID | None = None


class IncidentCreatedEvent(DomainEvent):
    """Evento disparado quando um novo incidente é criado pelo motor de correlação."""

    event_type: str = "IncidentCreatedEvent"
    incident_id: UUID
    correlation_key_hash: str
    severity: str
    triggering_event_id: UUID


class IncidentEvidenceAddedEvent(DomainEvent):
    """Evento disparado quando uma nova evidência é vinculada a um incidente existente."""

    event_type: str = "IncidentEvidenceAddedEvent"
    incident_id: UUID
    evidence_id: UUID
    event_id: UUID
