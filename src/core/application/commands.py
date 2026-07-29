"""
Commands Canônicos (CQRS M0.7)
GovSec Shield — Application Commands
"""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

DEV_TEST_TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")


class CommandMetadata(BaseModel):
    command_id: UUID = Field(default_factory=uuid4)
    command_name: str
    version: str = "1.0.0"
    tenant: str | UUID | None = None
    correlation_id: str = Field(default_factory=lambda: str(uuid4()))
    idempotency_key: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "api"
    requires_approval: bool = False


class Command(BaseModel):
    metadata: CommandMetadata
    payload: dict[str, Any]


class CreateTenantCommand(Command):
    def __init__(self, name: str, slug: str | None = None, **kwargs: Any):
        meta = CommandMetadata(command_name="CreateTenantCommand")
        payload = {"name": name, "slug": slug}
        super().__init__(metadata=meta, payload=payload)


class UpdateTenantCommand(Command):
    def __init__(
        self,
        tenant_id: UUID,
        name: str | None = None,
        status: str | None = None,
        **kwargs: Any,
    ):
        meta = CommandMetadata(command_name="UpdateTenantCommand", tenant=str(tenant_id))
        payload = {"tenant_id": str(tenant_id), "name": name, "status": status}
        super().__init__(metadata=meta, payload=payload)


class DeleteTenantCommand(Command):
    def __init__(self, tenant_id: UUID, **kwargs: Any):
        meta = CommandMetadata(command_name="DeleteTenantCommand", tenant=str(tenant_id))
        payload = {"tenant_id": str(tenant_id)}
        super().__init__(metadata=meta, payload=payload)


class IngestLogCommand(Command):
    def __init__(
        self,
        source: str,
        raw_data: str,
        tenant_id: UUID,
        timestamp: datetime | None = None,
        **kwargs: Any,
    ):
        meta = CommandMetadata(command_name="IngestLogCommand", tenant=str(tenant_id))
        payload = {
            "source": source,
            "raw_data": raw_data,
            "tenant_id": str(tenant_id),
            "timestamp": timestamp.isoformat() if timestamp else None,
        }
        super().__init__(metadata=meta, payload=payload)


class AcknowledgeAlertCommand(Command):
    def __init__(
        self,
        alert_id: str,
        fingerprint: str,
        reason: str,
        acknowledged_by: str,
        tenant_id: UUID | str = DEV_TEST_TENANT_ID,
        **kwargs: Any,
    ):
        meta = CommandMetadata(command_name="AcknowledgeAlertCommand", tenant=tenant_id)
        payload = {
            "alert_id": alert_id,
            "fingerprint": fingerprint,
            "reason": reason,
            "acknowledged_by": acknowledged_by,
            "tenant_id": tenant_id,
        }
        super().__init__(metadata=meta, payload=payload)
