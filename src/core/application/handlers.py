"""
Command Handlers da Aplicação
GovSec Shield — Command Handlers
"""

import re
from datetime import datetime, timezone
from uuid import UUID

from src.core.application.commands import (
    CreateTenantCommand,
    DeleteTenantCommand,
    IngestLogCommand,
    UpdateTenantCommand,
)
from src.core.application.dto import TenantResponseDTO
from src.core.application.interfaces import IEventPublisher
from src.core.domain.entities import AuditLog, Tenant, TenantStatus
from src.core.domain.events import LogIngestedEvent, TenantCreatedEvent
from src.core.domain.repositories import LogRepository, TenantRepository


class CreateTenantHandler:
    def __init__(self, tenant_repo: TenantRepository, event_publisher: IEventPublisher):
        self.tenant_repo = tenant_repo
        self.event_publisher = event_publisher

    async def handle(self, command: CreateTenantCommand) -> TenantResponseDTO:
        name = command.payload["name"]
        slug = command.payload.get("slug")

        if not slug:
            slug = re.sub(r"[^\w]+", "-", name.lower()).strip("-")

        existing = await self.tenant_repo.get_by_slug(slug)
        if existing:
            raise ValueError(f"Já existe um Tenant registrado com o slug '{slug}'")

        tenant = Tenant(name=name, slug=slug, status=TenantStatus.ACTIVE)

        saved = await self.tenant_repo.save(tenant)

        event = TenantCreatedEvent(tenant_id=saved.id, name=saved.name, slug=saved.slug)
        await self.event_publisher.publish(event)

        return TenantResponseDTO(
            id=saved.id,
            name=saved.name,
            slug=saved.slug,
            status=saved.status.value,
            created_at=saved.created_at,
            updated_at=saved.updated_at,
        )


class UpdateTenantHandler:
    def __init__(self, tenant_repo: TenantRepository):
        self.tenant_repo = tenant_repo

    async def handle(self, command: UpdateTenantCommand) -> TenantResponseDTO:
        tenant_id = UUID(command.payload["tenant_id"])
        tenant = await self.tenant_repo.get_by_id(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant com ID '{tenant_id}' não foi encontrado.")

        name = command.payload.get("name")
        status_str = command.payload.get("status")

        if name:
            tenant.update_name(name)
        if status_str:
            tenant.status = TenantStatus(status_str)
            tenant.updated_at = datetime.now(timezone.utc)

        saved = await self.tenant_repo.save(tenant)
        return TenantResponseDTO(
            id=saved.id,
            name=saved.name,
            slug=saved.slug,
            status=saved.status.value,
            created_at=saved.created_at,
            updated_at=saved.updated_at,
        )


class DeleteTenantHandler:
    def __init__(self, tenant_repo: TenantRepository):
        self.tenant_repo = tenant_repo

    async def handle(self, command: DeleteTenantCommand) -> bool:
        tenant_id = UUID(command.payload["tenant_id"])
        tenant = await self.tenant_repo.get_by_id(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant com ID '{tenant_id}' não foi encontrado.")

        return await self.tenant_repo.delete(tenant_id)


class IngestLogHandler:
    def __init__(self, event_publisher: IEventPublisher, log_repo: LogRepository | None = None):
        self.event_publisher = event_publisher
        self.log_repo = log_repo

    async def handle(self, command: IngestLogCommand) -> None:
        source = command.payload["source"]
        raw_data = command.payload["raw_data"]
        tenant_id_str = command.payload["tenant_id"]
        tenant_id = UUID(tenant_id_str)
        timestamp_str = command.payload.get("timestamp")
        timestamp = (
            datetime.fromisoformat(timestamp_str) if timestamp_str else datetime.now(timezone.utc)
        )

        log_entity = AuditLog(
            tenant_id=tenant_id,
            source=source,
            raw_data=raw_data if isinstance(raw_data, str) else str(raw_data),
            timestamp=timestamp,
        )
        if self.log_repo:
            await self.log_repo.save(log_entity)

        event = LogIngestedEvent(
            tenant_id=tenant_id, source=source, raw_data=raw_data, timestamp=timestamp
        )

        await self.event_publisher.publish(event)

