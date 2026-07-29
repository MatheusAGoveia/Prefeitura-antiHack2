"""
DTOs do Módulo Core
GovSec Shield — Application Layer DTOs
"""

from datetime import datetime
from typing import Any
from uuid import NAMESPACE_DNS, UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CreateTenantDTO(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    slug: str | None = Field(None, min_length=2, max_length=64)


class UpdateTenantDTO(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=128)
    status: str | None = Field(None, pattern="^(ACTIVE|INACTIVE|SUSPENDED)$")


class TenantResponseDTO(BaseModel):
    id: UUID
    name: str
    slug: str
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IngestLogDTO(BaseModel):
    source: str = Field(..., min_length=1, max_length=64)
    raw_data: str = Field(..., min_length=1)
    tenant_id: UUID
    timestamp: datetime | None = None

    @field_validator("tenant_id", mode="before")
    @classmethod
    def _validate_tenant_id(cls, v: Any) -> UUID:
        if isinstance(v, UUID):
            return v
        try:
            return UUID(str(v))
        except ValueError:
            return uuid5(NAMESPACE_DNS, str(v))


class LogResponseDTO(BaseModel):
    id: UUID
    source: str
    raw_data: str
    tenant_id: UUID
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class AcknowledgeAlertDTO(BaseModel):
    alert_id: str = Field(..., min_length=1, max_length=128, examples=["ServiceDown-Betim-01"])
    fingerprint: str = Field(..., min_length=1, max_length=128, examples=["a1b2c3d4e5f6"])
    reason: str = Field(..., min_length=5, max_length=512, examples=["Incidente verificado e servidor em reinício manual."])
    tenant_id: UUID | str | None = None

    @field_validator("tenant_id", mode="before")
    @classmethod
    def _validate_tenant_id(cls, v: Any) -> UUID | None:
        if v is None:
            return None
        if isinstance(v, UUID):
            return v
        try:
            return UUID(str(v))
        except ValueError:
            return uuid5(NAMESPACE_DNS, str(v))


class AlertAcknowledgementResponseDTO(BaseModel):
    id: UUID
    alert_id: str
    fingerprint: str
    reason: str
    acknowledged_by: str
    tenant_id: UUID
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)
