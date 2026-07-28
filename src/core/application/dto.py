"""
DTOs do Módulo Core
GovSec Shield — Application Layer DTOs
"""

from uuid import UUID
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict

class CreateTenantDTO(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    slug: Optional[str] = Field(None, min_length=2, max_length=64)

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
    timestamp: Optional[datetime] = None
