"""
Entidades e Value Objects do Domínio Core
GovSec Shield — Domain Layer
"""

from datetime import datetime, timezone
from enum import StrEnum
from typing import NewType
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

TenantId = NewType("TenantId", UUID)


class TenantStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    SUSPENDED = "SUSPENDED"


class Tenant(BaseModel):
    """
    Entidade Tenant no Domínio Core.
    """

    id: UUID = Field(default_factory=uuid4)
    name: str = Field(..., min_length=2, max_length=128)
    slug: str = Field(..., min_length=2, max_length=64)
    status: TenantStatus = Field(default=TenantStatus.ACTIVE)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def update_name(self, new_name: str) -> None:
        self.name = new_name
        self.updated_at = datetime.now(timezone.utc)

    def deactivate(self) -> None:
        self.status = TenantStatus.INACTIVE
        self.updated_at = datetime.now(timezone.utc)

    def activate(self) -> None:
        self.status = TenantStatus.ACTIVE
        self.updated_at = datetime.now(timezone.utc)


class AuditLog(BaseModel):
    """
    Entidade de Log de Auditoria no Domínio Core.
    """

    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    source: str = Field(..., min_length=1, max_length=64)
    raw_data: str = Field(..., min_length=1)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AlertAcknowledgement(BaseModel):
    """
    Entidade de Acknowledgement Humano de Alerta.
    """

    id: UUID = Field(default_factory=uuid4)
    alert_id: str = Field(..., min_length=1, max_length=128)
    fingerprint: str = Field(..., min_length=1, max_length=128)
    reason: str = Field(..., min_length=1, max_length=512)
    acknowledged_by: str = Field(..., min_length=1, max_length=128)
    tenant_id: str = Field(..., min_length=1, max_length=64)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


