"""
Eventos de Domínio Core
GovSec Shield — Domain Events
"""

from typing import Optional
from uuid import UUID, uuid4
from datetime import datetime
from pydantic import BaseModel, Field

class DomainEvent(BaseModel):
    """Envelope base para eventos de domínio conforme M0.6."""
    event_id: UUID = Field(default_factory=uuid4)
    event_type: str
    tenant_id: Optional[UUID] = None
    occurred_at: datetime = Field(default_factory=datetime.utcnow)
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
    timestamp: datetime = Field(default_factory=datetime.utcnow)
