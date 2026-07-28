"""
Commands Canônicos (CQRS M0.7)
GovSec Shield — Application Commands
"""

from uuid import UUID, uuid4
from datetime import datetime
from typing import Optional, Any, Dict
from pydantic import BaseModel, Field

class CommandMetadata(BaseModel):
    command_id: UUID = Field(default_factory=uuid4)
    command_name: str
    version: str = "1.0.0"
    tenant: Optional[str] = None
    correlation_id: str = Field(default_factory=lambda: str(uuid4()))
    idempotency_key: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    source: str = "api"
    requires_approval: bool = False

class Command(BaseModel):
    metadata: CommandMetadata
    payload: Dict[str, Any]

class CreateTenantCommand(Command):
    def __init__(self, name: str, slug: Optional[str] = None, **kwargs: Any):
        meta = CommandMetadata(command_name="CreateTenantCommand")
        payload = {"name": name, "slug": slug}
        super().__init__(metadata=meta, payload=payload)

class IngestLogCommand(Command):
    def __init__(self, source: str, raw_data: str, tenant_id: UUID, timestamp: Optional[datetime] = None, **kwargs: Any):
        meta = CommandMetadata(command_name="IngestLogCommand", tenant=str(tenant_id))
        payload = {
            "source": source,
            "raw_data": raw_data,
            "tenant_id": str(tenant_id),
            "timestamp": timestamp.isoformat() if timestamp else None
        }
        super().__init__(metadata=meta, payload=payload)
