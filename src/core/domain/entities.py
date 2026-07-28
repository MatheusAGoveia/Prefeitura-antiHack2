"""
Entidades e Value Objects do Domínio Core
GovSec Shield — Domain Layer
"""

from enum import StrEnum
from uuid import UUID, uuid4
from datetime import datetime
from typing import NewType, Optional
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
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def deactivate(self) -> None:
        self.status = TenantStatus.INACTIVE
        self.updated_at = datetime.utcnow()

    def activate(self) -> None:
        self.status = TenantStatus.ACTIVE
        self.updated_at = datetime.utcnow()
